// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"crypto/rc4"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

// negotiatorBody wraps an io.ReadSeeker to allow waiting for its closure
// before rewinding and reusing it.
type negotiatorBody struct {
	body     io.ReadSeeker
	closed   chan struct{}
	startPos int64
}

// newNegotiatorBody creates a negotiatorBody from the provided io.Reader.
// If the body is nil, it returns nil.
// If the body is already an io.ReadSeeker, it uses it directly.
// Otherwise, it reads the entire body into memory to allow rewinding.
func newNegotiatorBody(body io.Reader) (*negotiatorBody, error) {
	if body == nil {
		return nil, nil
	}
	// Check if body is already seekable to avoid buffering large bodies
	if seeker, ok := body.(io.ReadSeeker); ok {
		// Remember the current position
		startPos, err := seeker.Seek(0, io.SeekCurrent)
		if err == nil {
			// Seeking succeeded, use the seekable body directly
			return &negotiatorBody{
				body:     seeker,
				closed:   make(chan struct{}, 1),
				startPos: startPos,
			}, nil
		}
		// Seeking failed (e.g., pipes), fallback to buffering
	}
	// For non-seekable bodies, buffer in memory as required
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return &negotiatorBody{
		body:   bytes.NewReader(data),
		closed: make(chan struct{}, 1),
	}, nil
}

func (b *negotiatorBody) Read(p []byte) (n int, err error) {
	if b == nil {
		return 0, io.EOF
	}
	return b.body.Read(p)
}

// Close signals that the body is no longer needed for the current request.
// It allows the negotiator to rewind the body for potential reuse.
// The underlying body is not closed here; use close() for that.
func (b *negotiatorBody) Close() error {
	if b == nil {
		return nil
	}
	select {
	case b.closed <- struct{}{}:
	default:
		// Already signaled
	}
	return nil
}

// close closes the underlying body if it implements io.Closer.
func (b *negotiatorBody) close() {
	if b == nil {
		return
	}
	if closer, ok := b.body.(io.Closer); ok {
		_ = closer.Close()
	}
}

// rewind rewinds the body to the start position for reuse.
func (b *negotiatorBody) rewind() error {
	if b == nil {
		return nil
	}
	// Wait for the body to be closed before rewinding
	<-b.closed
	_, err := b.body.Seek(b.startPos, io.SeekStart)
	return err
}

// GetDomain extracts the user domain from the username if present.
//
// Deprecated: Pass the username directly to [ProcessChallenge], it will handle domain extraction.
// Don't pass the resulting domain to [NewNegotiateMessage], that function expects the client
// machine domain, not the user domain.
func GetDomain(username string) (user string, domain string, domainNeeded bool) {
	if strings.Contains(username, "\\") {
		ucomponents := strings.SplitN(username, "\\", 2)
		domain = ucomponents[0]
		user = ucomponents[1]
		domainNeeded = true
	} else if strings.Contains(username, "@") {
		user = username
		domainNeeded = false
	} else {
		user = username
		domainNeeded = true
	}
	return user, domain, domainNeeded
}

// Negotiator is a [net/http.RoundTripper] decorator that automatically
// converts basic authentication to NTLM/Negotiate authentication when appropriate.
//
// The credentials must be set using [net/http.Request.SetBasicAuth] on a per-request basis.
//
// By default, no credentials will be sent to the server unless it requests
// Basic authentication and [Negotiator.AllowBasicAuth] is set to true.
type Negotiator struct {
	// RoundTripper is the underlying round tripper to use.
	// If nil, http.DefaultTransport is used.
	http.RoundTripper

	// AllowBasicAuth controls whether to send Basic authentication credentials
	// if the server requests it.
	//
	// If false (default), Basic authentication requests are ignored
	// and only NTLM/Negotiate authentication is performed.
	// If true, Basic authentication requests are honored.
	//
	// Only set this to true if you trust the server you are connecting to.
	// Basic authentication sends the credentials in clear text and may be
	// vulnerable to man-in-the-middle attacks and compromised servers.
	AllowBasicAuth bool

	// WorkstationDomain is the domain of the client machine.
	// It is normally not needed to set this field.
	// It is passed to the negotiate message.
	WorkstationDomain string

	// WorkstationName is the workstation name of the client machine.
	// It is passed to the negotiate and authenticate messages.
	// Useful for auditing purposes on the server side.
	WorkstationName string

	// ExportedSessionKey is the session key exported from the completed handshake.
	// It is only set if the server requested NTLMSSP_NEGOTIATE_KEY_EXCH and the handshake completed successfully.
	// It is used for signing and sealing messages after the handshake.
	ExportedSessionKey []byte

	// Seal/sign state derived from ExportedSessionKey. Initialized once per session.
	// RC4 cipher handles are persistent across messages (MS-NLMP §3.4 CONNECTION mode).
	// seqNum increments per sealed message for replay protection.
	clientSealCipher *rc4.Cipher
	clientSignKey    []byte
	serverSealCipher *rc4.Cipher
	serverSignKey    []byte
	clientSeqNum     uint32

	// Cached credentials for stale-session re-authentication.
	// cachedNtlmV2Hash is derived from the password at handshake time so the raw
	// password does not need to be retained. It is stable across sessions because it
	// depends only on username, domain, and password — not on any per-session values
	// (timestamp, server challenge, client challenge).
	cachedUsername   string
	cachedNtlmV2Hash []byte

	mu sync.Mutex
}

// RoundTrip sends the request to the server, handling any authentication
// re-sends as needed.
func (l *Negotiator) RoundTrip(req *http.Request) (*http.Response, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Use default round tripper if not provided
	rt := l.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}

	// If it is not basic auth, just round trip the request as usual
	username, password, ok := req.BasicAuth()
	if !ok {
		usedSessionKey := l.clientSealCipher != nil

		// Read plaintext body before sealing so we can re-seal it after a stale-session
		// re-authentication without having to ask the caller to retry.
		var plainBody []byte
		if usedSessionKey && req.Body != nil {
			var bodyErr error
			plainBody, bodyErr = io.ReadAll(req.Body)
			if bodyErr != nil {
				return nil, bodyErr
			}
			_ = req.Body.Close()
		}

		if usedSessionKey {
			if err := SealRequest(req, io.NopCloser(bytes.NewReader(plainBody)), l.clientSealCipher, l.clientSignKey, l.clientSeqNum); err != nil {
				return nil, err
			}
			l.clientSeqNum++
		}

		resp, err := rt.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		// The session may have gone stale (server restart, session expiry). Re-authenticate
		// transparently using the cached NTLMv2 hash if we have one.
		if usedSessionKey && resp.StatusCode == http.StatusUnauthorized && len(l.cachedNtlmV2Hash) > 0 {
			drainResponse(resp)
			l.resetSession()

			resauth := newAuthHeader(resp.Header)
			if !resauth.isNTLM() {
				return nil, errors.New("stale session: server did not issue an NTLM/Negotiate challenge")
			}

			// Step 1: NEGOTIATE
			req.Body = nil
			req.ContentLength = 0
			resp = clientHandshake(rt, req, resauth.schema, l.WorkstationDomain, l.WorkstationName)
			if resp == nil {
				return nil, errors.New("stale session: NTLM negotiate failed")
			}
			if resp.StatusCode != http.StatusUnauthorized {
				return resp, nil
			}
			resauth = newAuthHeader(resp.Header)
			drainResponse(resp)

			// Step 2: AUTHENTICATE using cached NTLMv2 hash
			var sessionKey []byte
			resp, sessionKey = completeHandshakeWithHash(rt, resauth, req, l.cachedUsername, l.cachedNtlmV2Hash, l.WorkstationName, plainBody)
			if resp == nil {
				return nil, errors.New("stale session: NTLM authenticate failed")
			}

			if len(sessionKey) > 0 {
				l.ExportedSessionKey = sessionKey
				l.clientSignKey = NewClientSignKey(sessionKey)
				clientSealKey := NewClientSealKey(sessionKey)
				l.clientSealCipher, _ = rc4.NewCipher(clientSealKey)
				l.serverSignKey = NewServerSignKey(sessionKey)
				serverSealKey := NewServerSealKey(sessionKey)
				l.serverSealCipher, _ = rc4.NewCipher(serverSealKey)
				l.clientSeqNum = 0
			}

			// For Negotiate, the body was withheld from the authenticate message;
			// send it now, sealed with the new session key.
			if resauth.isNegotiate() && l.clientSealCipher != nil {
				if err := SealRequest(req, io.NopCloser(bytes.NewReader(plainBody)), l.clientSealCipher, l.clientSignKey, l.clientSeqNum); err != nil {
					return resp, nil
				}
				l.clientSeqNum++
				req.Header.Del("Authorization")
				drainResponse(resp)
				resp, err = rt.RoundTrip(req)
				if err != nil {
					return nil, err
				}
				if err = UnsealResponse(resp, l.serverSealCipher, l.serverSignKey); err != nil {
					return resp, err
				}
			}

			return resp, nil
		}

		if usedSessionKey {
			if err = UnsealResponse(resp, l.serverSealCipher, l.serverSignKey); err != nil {
				return resp, err
			}
		}

		return resp, nil
	}
	id := identity{
		username: username,
		password: password,
	}

	req = req.Clone(req.Context()) // Clone the request to avoid modifying the original

	// We need to buffer or seek the request body to handle authentication challenges
	// that require resending the body multiple times during the NTLM handshake.
	body, err := newNegotiatorBody(req.Body)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	defer body.close()

	// First try anonymous, in case the server still finds us authenticated from previous traffic
	req.Body = body
	req.Header.Del("Authorization")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		// No authentication required, return the response as is
		return resp, nil
	}

	// Note that from here on, the response returned in case of error or unsuccessful
	// negotiation is the one we just got from the server. This is to allow the caller
	// to do its own handling in case we can't do it in this roundtrip.
	originalResp := resp

	resauth := newAuthHeader(resp.Header)
	if l.AllowBasicAuth && resauth.isBasic() {
		// Basic auth requested instead of NTLM/Negotiate.
		//
		// Rewind the body, we will resend it.
		if body.rewind() != nil {
			return originalResp, nil
		}
		req.SetBasicAuth(id.username, id.password)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			return originalResp, nil
		}
		if resp.StatusCode != http.StatusUnauthorized {
			// Basic auth succeeded, return the new response
			drainResponse(originalResp)
			return resp, nil
		}
		resauth = newAuthHeader(resp.Header)
		if !resauth.isNTLM() {
			// No NTLM/Negotiate requested, return the response as is
			return resp, nil
		}
		// Server upgraded from Basic to NTLM/Negotiate (rare but possible)
		drainResponse(resp)
		// After Basic-to-NTLM upgrade, update originalResp to the NTLM-triggering response
		originalResp = resp
	} else if !resauth.isNTLM() {
		// No NTLM/Negotiate requested, return the response as is
		return originalResp, nil
	}

	// Server requested Negotiate/NTLM, start handshake

	// First step: send negotiate message
	resp = clientHandshake(rt, req, resauth.schema, l.WorkstationDomain, l.WorkstationName)
	if resp == nil {
		return originalResp, nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		// We are expecting a 401 with challenge, but the server responded differently,
		// maybe it even accepted our negotiate message without further challenge, which is
		// valid per the spec (RFC 4559 Section 5).
		// Return the response as is, negotiation is over.
		drainResponse(originalResp)
		return resp, nil
	}
	resauth = newAuthHeader(resp.Header)
	drainResponse(resp)

	// Second step: process challenge and resend the original body with the authenticate message
	var sessionKey []byte
	resp, sessionKey = completeHandshake(rt, resauth, req, id, l.WorkstationName)
	if resp == nil {
		return originalResp, nil
	}

	if len(sessionKey) > 0 {
		l.ExportedSessionKey = sessionKey
		l.clientSignKey = NewClientSignKey(sessionKey)
		clientSealKey := NewClientSealKey(sessionKey)
		l.clientSealCipher, _ = rc4.NewCipher(clientSealKey)
		l.serverSignKey = NewServerSignKey(sessionKey)
		serverSealKey := NewServerSealKey(sessionKey)
		l.serverSealCipher, _ = rc4.NewCipher(serverSealKey)
		l.clientSeqNum = 0

		// Cache credentials for transparent stale-session re-authentication.
		// We store the NTLMv2 hash rather than the raw password; the hash is stable
		// across sessions and cannot be trivially reversed to recover the password.
		l.cachedUsername = id.username
		l.cachedNtlmV2Hash = ntlmV2HashFor(id.username, id.password)
	}

	// For Negotiate, authenticate was sent without the body; send it sealed now.
	if resauth.isNegotiate() && l.clientSealCipher != nil {
		if err := SealRequest(req, body, l.clientSealCipher, l.clientSignKey, l.clientSeqNum); err != nil {
			return originalResp, nil
		}
		l.clientSeqNum++
		req.Header.Del("Authorization")
		drainResponse(resp)
		resp, err = rt.RoundTrip(req)
		if err != nil {
			return originalResp, nil
		}
		if err = UnsealResponse(resp, l.serverSealCipher, l.serverSignKey); err != nil {
			return resp, err
		}
	}

	drainResponse(originalResp)
	return resp, nil
}

type identity struct {
	username string
	password string
}

func drainResponse(res *http.Response) {
	// Drain body and close it to allow reusing the connection
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
}

func rewindBody(req *http.Request) error {
	if req.Body == nil {
		return nil
	}
	if nb, ok := req.Body.(*negotiatorBody); ok {
		return nb.rewind()
	}
	return nil
}

// ntlmV2HashFor computes the NTLMv2 hash from a plain-text username and password.
// The result is stable (no per-session values) and can be cached to avoid retaining
// the raw password.
func ntlmV2HashFor(username, password string) []byte {
	user, domain := splitNameForAuth(username)
	return getNtlmV2Hash(password, user, domain)
}

func clientHandshake(rt http.RoundTripper, req *http.Request, schema string, domain, workstation string) *http.Response {
	if rewindBody(req) != nil {
		return nil
	}
	auth, err := NewNegotiateMessage(domain, workstation)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", schema+" "+base64.StdEncoding.EncodeToString(auth))
	res, err := rt.RoundTrip(req)
	if err != nil {
		return nil
	}
	return res
}

// completeHandshake sends the AUTHENTICATE message and returns the server response along with
// the exported session key. The session key is nil when NTLMSSP_NEGOTIATE_KEY_EXCH was not
// negotiated; callers that only need the response may discard it with _.
func completeHandshake(rt http.RoundTripper, resauth authheader, req *http.Request, id identity, workstation string) (*http.Response, []byte) {
	if rewindBody(req) != nil {
		return nil, nil
	}
	challenge, err := resauth.token()
	if err != nil {
		return nil, nil
	}
	if !resauth.isNTLM() || len(challenge) == 0 {
		// The only expected schema here is NTLM/Negotiate with a challenge token,
		// otherwise the negotiation is over.
		return nil, nil
	}
	var opts *AuthenticateMessageOptions
	if workstation != "" {
		opts = &AuthenticateMessageOptions{
			WorkstationName: workstation,
		}
	}
	auth, sessionKey, err := newAuthenticateMessageInternal(challenge, id.username, id.password, opts)
	if err != nil {
		return nil, nil
	}

	if resauth.isNegotiate() {
		req.Body = nil // Negotiate does not support body in authenticate message
	}

	req.Header.Set("Authorization", resauth.schema+" "+base64.StdEncoding.EncodeToString(auth))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, nil
	}

	return resp, sessionKey
}

// completeHandshakeWithHash is like completeHandshake but uses a pre-computed NTLMv2 hash
// instead of a raw password. plainBody is the plaintext request body that should accompany
// the AUTHENTICATE message for NTLM (for Negotiate it is sent separately after the handshake).
func completeHandshakeWithHash(rt http.RoundTripper, resauth authheader, req *http.Request, username string, ntlmV2Hash []byte, workstation string, plainBody []byte) (*http.Response, []byte) {
	challenge, err := resauth.token()
	if err != nil {
		return nil, nil
	}
	if !resauth.isNTLM() || len(challenge) == 0 {
		return nil, nil
	}
	auth, sessionKey, err := buildAuthenticateMessageFromHash(challenge, username, ntlmV2Hash, workstation)
	if err != nil {
		return nil, nil
	}

	if resauth.isNegotiate() {
		req.Body = nil // body is sent separately after the handshake, sealed with the new session key
	} else {
		req.Body = io.NopCloser(bytes.NewReader(plainBody))
	}

	req.Header.Set("Authorization", resauth.schema+" "+base64.StdEncoding.EncodeToString(auth))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, nil
	}
	return resp, sessionKey
}
