// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
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
}

// RoundTrip sends the request to the server, handling any authentication
// re-sends as needed.
func (l *Negotiator) RoundTrip(req *http.Request) (*http.Response, error) {
	// Use default round tripper if not provided
	rt := l.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}

	// If it is not basic auth, just round trip the request as usual
	username, password, ok := req.BasicAuth()
	if !ok {
		return rt.RoundTrip(req)
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

	if len(l.ExportedSessionKey) > 0 {
		// If we have an exported session key from a previous handshake, try sealing the request right away.
		err = SealRequest(req, body, l.ExportedSessionKey)
		if err != nil {
			return nil, err
		}
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if len(l.ExportedSessionKey) > 0 {
		// If we have an exported session key, try unsealing the response right away.
		err = UnsealResponse(resp, l.ExportedSessionKey)
		if err != nil {
			return resp, err
		}
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
	resp, l.ExportedSessionKey = completeHandshake(rt, resauth, req, id, l.WorkstationName)
	if resp == nil {
		return originalResp, nil
	}
	// We could return the original response in case of 401 again, but at this point
	// it's better to return the latest response from the server, as it might be the case
	// that we are really not authorized.
	drainResponse(originalResp) // Done with the original response
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

	body := req.Body
	if resauth.isNegotiate() {
		req.Body = nil // Negotiate does not support body in authenticate message
	}

	req.Header.Set("Authorization", resauth.schema+" "+base64.StdEncoding.EncodeToString(auth))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, nil
	}

	if resauth.isNegotiate() {
		err = SealRequest(req, body, sessionKey)
		if err != nil {
			return nil, nil
		}

		req.Header.Del("Authorization")
		drainResponse(resp)
		resp, err = rt.RoundTrip(req)
		if err != nil {
			return nil, nil
		}

		err = UnsealResponse(resp, sessionKey)
		if err != nil {
			return nil, nil
		}
	}

	return resp, sessionKey
}

const CLIENT_TO_SERVER_SIGNING = "session key to client-to-server signing key magic constant"
const CLIENT_TO_SERVER_SEALING = "session key to client-to-server sealing key magic constant"
const SERVER_TO_CLIENT_SIGNING = "session key to server-to-client signing key magic constant"
const SERVER_TO_CLIENT_SEALING = "session key to server-to-client sealing key magic constant"
const VERSION_MAGIC = "\x01\x00\x00\x00"

func rc4k(key []byte, data []byte) (out []byte, cipher *rc4.Cipher, err error) {
	cipher, err = rc4.NewCipher(key)
	if err != nil {
		return
	}
	out = make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return
}

func sign(sealCipher *rc4.Cipher, signKey []byte, seq []byte, plaintext []byte) []byte {
	encHmac := make([]byte, 8)
	sealCipher.XORKeyStream(encHmac, hmacMd5(signKey, append(seq, plaintext...))[:8])
	// NTLMSSP_MESSAGE_SIGNATURE (16 bytes): version(4) | encHmac(8) | seq(4)
	return slices.Concat([]byte(VERSION_MAGIC), encHmac, seq)
}

func SealRequest(req *http.Request, body io.ReadCloser, sessionKey []byte) error {
	// Derive signing and sealing keys (MS-NLMP §3.4.5.2).
	clientSignKey := NewClientSignKey(sessionKey)
	clientSealKey := NewClientSealKey(sessionKey)

	// Read the plaintext body once — used for both HMAC and encryption below.
	plaintext, readErr := io.ReadAll(body)
	if readErr != nil {
		return nil
	}

	seq := []byte{0, 0, 0, 0} // sequence number 0 (LE)

	// seal the message
	encBody, sealCipher, err := rc4k(clientSealKey, plaintext)
	if err != nil {
		return nil
	}

	// sign the message
	sig := sign(sealCipher, clientSignKey, seq, plaintext)

	// Binary payload per MS-WSMV §3.1.4.2:
	payload := slices.Concat([]byte{16, 0, 0, 0}, sig, encBody)

	// Multipart/encrypted body (MS-WSMV §3.1.4.2)
	var multipartBody bytes.Buffer
	multipartBody.WriteString("--Encrypted Boundary\r\n")
	multipartBody.WriteString("Content-Type: application/HTTP-SPNEGO-session-encrypted\r\n")
	multipartBody.WriteString("OriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + strconv.Itoa(len(plaintext)) + "\r\n")
	multipartBody.WriteString("--Encrypted Boundary\r\n")
	multipartBody.WriteString("Content-Type: application/octet-stream\r\n")
	multipartBody.Write(payload)
	multipartBody.WriteString("--Encrypted Boundary--\r\n")

	req.Body = io.NopCloser(&multipartBody)
	req.ContentLength = int64(multipartBody.Len())
	req.Header.Set("Content-Type", `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`)

	return nil
}

func UnsealResponse(resp *http.Response, sessionKey []byte) error {
	if !strings.Contains(resp.Header.Get("Content-Type"), "multipart/encrypted") {
		// Not an encrypted response; leave it untouched.
		return nil
	}

	serverSignKey := NewServerSignKey(sessionKey)
	serverSealKey := NewServerSealKey(sessionKey)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var emessage []byte
	for boundary := range bytes.SplitSeq(body, []byte("--Encrypted Boundary")) {
		if header, ok := bytes.CutPrefix(boundary, []byte("\r\nContent-Type: application/HTTP-SPNEGO-session-encrypted\r\nOriginalContent: ")); ok {
			header = bytes.TrimSuffix(header, []byte("\r\n"))
			for part := range bytes.SplitSeq(header, []byte(";")) {
				if after, ok := bytes.CutPrefix(part, []byte("Length=")); ok {
					length, err := strconv.ParseInt(string(after), 10, 64)
					if err != nil {
						return errors.New("invalid length in encrypted message header")
					}
					resp.ContentLength = int64(length)
					resp.Header.Set("Content-Length", string(after))
				} else if contentType, ok := bytes.CutPrefix(part, []byte("type=")); ok {
					resp.Header.Set("Content-Type", string(contentType))
				}
			}
		} else if data, ok := bytes.CutPrefix(boundary, []byte("\r\nContent-Type: application/octet-stream\r\n")); ok {
			emessage = data
		}
	}

	if len(emessage) < 20 {
		return errors.New("encrypted part too short to contain signature")
	}

	signature := emessage[4:20]
	ciphertext := emessage[20:]

	plaintext, cipher, err := rc4k(serverSealKey, ciphertext)
	if err != nil {
		return err
	}

	expectedSig := sign(cipher, serverSignKey, signature[12:16], plaintext)
	if !bytes.Equal(signature, expectedSig) {
		return errors.New("invalid signature in sealed response")
	}

	resp.Body = io.NopCloser(bytes.NewReader(plaintext))
	return nil
}

func NewClientSignKey(sessionKey []byte) []byte {
	return newSessionKey(sessionKey, CLIENT_TO_SERVER_SIGNING)
}

func NewClientSealKey(sessionKey []byte) []byte {
	return newSessionKey(sessionKey, CLIENT_TO_SERVER_SEALING)
}

func NewServerSignKey(sessionKey []byte) []byte {
	return newSessionKey(sessionKey, SERVER_TO_CLIENT_SIGNING)
}

func NewServerSealKey(sessionKey []byte) []byte {
	return newSessionKey(sessionKey, SERVER_TO_CLIENT_SEALING)
}

func newSessionKey(sessionKey []byte, magicConstant string) []byte {
	keyIn := slices.Concat(sessionKey, []byte(magicConstant), []byte{0})
	keyArr := md5.Sum(keyIn)
	return keyArr[:]
}
