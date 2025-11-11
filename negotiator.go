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

// closeWaiter wraps an io.ReadSeeker and signals when Close is called,
// allowing us to wait before reusing the body after RoundTrip returns.
type closeWaiter struct {
	io.ReadSeeker
	closed chan struct{}
	once   sync.Once
}

func newCloseWaiter(rs io.ReadSeeker) *closeWaiter {
	return &closeWaiter{
		ReadSeeker: rs,
		closed:     make(chan struct{}),
	}
}

func (cw *closeWaiter) Close() error {
	cw.once.Do(func() {
		close(cw.closed)
	})
	return nil
}

func (cw *closeWaiter) waitForClose() {
	<-cw.closed
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
	reqauth := authheader(req.Header.Values("Authorization"))
	if !reqauth.IsBasic() {
		return rt.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	reqauthBasic := reqauth.Basic()
	// We need to buffer or seek the request body to handle authentication challenges
	// that require resending the body multiple times during the NTLM handshake.
	var body io.ReadSeeker
	var bodyStartPos int64
	var bodyWrapper *closeWaiter
	if req.Body != nil {
		// Check if body is already seekable to avoid buffering large bodies
		if seeker, ok := req.Body.(io.ReadSeeker); ok {
			// Remember the current position
			bodyStartPos, err = seeker.Seek(0, io.SeekCurrent)
			if err == nil {
				// Seeking succeeded, use the seekable body directly
				body = seeker
				// Close the original body as mandated by http.RoundTripper
				defer req.Body.Close()
			} else {
				// Seeking failed (e.g., pipes), fallback to buffering
				bodyBytes, err := io.ReadAll(req.Body)
				req.Body.Close()
				if err != nil {
					return nil, err
				}
				body = bytes.NewReader(bodyBytes)
				bodyStartPos = 0
			}
		} else {
			// For non-seekable bodies, buffer in memory as required
			bodyBytes, err := io.ReadAll(req.Body)
			req.Body.Close()
			if err != nil {
				return nil, err
			}
			body = bytes.NewReader(bodyBytes)
			bodyStartPos = 0
		}
		bodyWrapper = newCloseWaiter(body)
		req.Body = bodyWrapper
	}
	// first try anonymous, in case the server still finds us
	// authenticated from previous traffic
	req.Header.Del("Authorization")
	res, err = rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusUnauthorized {
		return res, err
	}
	resauth := authheader(res.Header.Values("Www-Authenticate"))
	if !resauth.IsNegotiate() && !resauth.IsNTLM() {
		// Unauthorized, Negotiate not requested, let's try with basic auth
		req.Header.Set("Authorization", reqauthBasic)
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if body != nil {
			// Wait for the wrapped RoundTripper to finish with the body
			bodyWrapper.waitForClose()
			_, err = body.Seek(bodyStartPos, io.SeekStart)
			if err != nil {
				return nil, err
			}
			bodyWrapper = newCloseWaiter(body)
			req.Body = bodyWrapper
		}

		res, err = rt.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusUnauthorized {
			return res, err
		}
		resauth = authheader(res.Header.Values("Www-Authenticate"))
	}

	if resauth.IsNegotiate() || resauth.IsNTLM() {
		// 401 with request:Basic and response:Negotiate
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()

		// recycle credentials
		u, p, err := reqauth.GetBasicCreds()
		if err != nil {
			return nil, err
		}

		// get domain from username
		domain := ""
		u, domain, domainNeeded := GetDomain(u)

		// send negotiate
		negotiateMessage, err := NewNegotiateMessage(domain, "")
		if err != nil {
			return nil, err
		}
		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiateMessage))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiateMessage))
		}

		if body != nil {
			// Wait for the wrapped RoundTripper to finish with the body
			bodyWrapper.waitForClose()
			_, err = body.Seek(bodyStartPos, io.SeekStart)
			if err != nil {
				return nil, err
			}
			bodyWrapper = newCloseWaiter(body)
			req.Body = bodyWrapper
		}

		res, err = rt.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		// receive challenge?
		resauth = authheader(res.Header.Values("Www-Authenticate"))
		challengeMessage, err := resauth.GetData()
		if err != nil {
			return nil, err
		}
		if !(resauth.IsNegotiate() || resauth.IsNTLM()) || len(challengeMessage) == 0 {
			// Negotiation failed, let client deal with response
			return res, nil
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()

		// send authenticate
		authenticateMessage, err := ProcessChallenge(challengeMessage, u, p, domainNeeded)
		if err != nil {
			return nil, err
		}
		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticateMessage))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authenticateMessage))
		}

		if body != nil {
			// Wait for the wrapped RoundTripper to finish with the body
			bodyWrapper.waitForClose()
			_, err = body.Seek(bodyStartPos, io.SeekStart)
			if err != nil {
				return nil, err
			}
			bodyWrapper = newCloseWaiter(body)
			req.Body = bodyWrapper
		}

		return rt.RoundTrip(req)
	}

	return res, err
}
