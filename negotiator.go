// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"encoding/base64"
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
	once     sync.Once
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
				closed:   make(chan struct{}),
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
		closed: make(chan struct{}),
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
	b.once.Do(func() {
		close(b.closed)
	})
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
	<-b.closed
	_, err := b.body.Seek(b.startPos, io.SeekStart)
	return err
}

// GetDomain extracts the domain from the username if present.
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

// Negotiator is a http.Roundtripper decorator that automatically
// converts basic authentication to NTLM/Negotiate authentication when appropriate.
type Negotiator struct{ http.RoundTripper }

// RoundTrip sends the request to the server, handling any authentication
// re-sends as needed.
func (l Negotiator) RoundTrip(req *http.Request) (res *http.Response, err error) {
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
	id := &identity{
		username: username,
		password: password,
	}
	req = req.Clone(req.Context())
	// We need to buffer or seek the request body to handle authentication challenges
	// that require resending the body multiple times during the NTLM handshake.
	body, err := newNegotiatorBody(req.Body)
	if err != nil {
		return nil, err
	}
	defer body.close()
	if req.Body != nil {
		req.Body = body
	}
	// First try anonymous, in case the server still finds us authenticated from previous traffic
	res, done, err := doRequest(req, rt, "", nil, nil)
	if done {
		return res, err
	}

	resauth := newAuthHeader(res.Header)
	if !resauth.isNTLM() {
		// Unauthorized, Negotiate not requested, let's try with basic auth
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if err := body.rewind(); err != nil {
			return nil, err
		}
		res, done, err = doRequest(req, rt, "Basic", id, nil)
		if done {
			return res, err
		}
		resauth = newAuthHeader(res.Header)
		if !resauth.isNTLM() {
			// Nothing to negotiate, let client deal with response
			return res, err
		}
	}

	// Server requested Negotiate/NTLM, start the handshake
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if err := body.rewind(); err != nil {
		return nil, err
	}
	res, done, err = doRequest(req, rt, resauth.schema, id, nil)
	if done {
		return res, err
	}

	// Server should have responded with a challenge
	resauth = newAuthHeader(res.Header)
	challengeMessage, err := resauth.token()
	if err != nil {
		return nil, err
	}
	if !resauth.isNTLM() || len(challengeMessage) == 0 {
		// Negotiation failed, let client deal with response
		return res, nil
	}

	// Resend message with challenge response
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if err := body.rewind(); err != nil {
		return nil, err
	}
	res, _, err = doRequest(req, rt, resauth.schema, id, challengeMessage)
	return res, err
}

type identity struct {
	username string
	password string
}

// doRequest performs a single HTTP request with the specified authentication schema and identity.
// It returns the response, a boolean indicating if no further authentication is needed, and any error encountered.
func doRequest(req *http.Request, rt http.RoundTripper, authSchema string, id *identity, challenge []byte) (res *http.Response, done bool, err error) {
	switch authSchema {
	case "":
		if id != nil {
			panic("identity provided with empty auth schema")
		}
		req.Header.Del("Authorization")
	case "Basic":
		if id == nil {
			panic("identity required for basic auth")
		}
		req.SetBasicAuth(id.username, id.password)
	case "NTLM", "Negotiate":
		if id == nil {
			panic("identity required for NTLM/Negotiate auth")
		}
		var auth []byte
		if challenge == nil {
			// First step: send negotiate message
			_, domain, _ := GetDomain(id.username)
			auth, err = NewNegotiateMessage(domain, "")
			if err != nil {
				return nil, true, err
			}
		} else {
			// Second step: send authenticate message
			user, _, domainNeeded := GetDomain(id.username)
			auth, err = ProcessChallenge(challenge, user, id.password, domainNeeded)
			if err != nil {
				return nil, true, err
			}
		}
		req.Header.Set("Authorization", authSchema+" "+base64.StdEncoding.EncodeToString(auth))
	default:
		panic("unreachable")
	}
	res, err = rt.RoundTrip(req)
	if err != nil {
		return res, true, err
	}
	return res, res.StatusCode != http.StatusUnauthorized, nil
}
