// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
)

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
	reqauthBasic := reqauth.Basic()
	// Save request body as a seekable reader to avoid duplication
	var bodySeeker io.ReadSeeker
	if req.Body != nil {
		// Check if body is already seekable to avoid buffering large bodies
		if seeker, ok := req.Body.(io.ReadSeeker); ok {
			bodySeeker = seeker
		} else {
			// For non-seekable bodies, buffer in memory (backward compatibility)
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			req.Body.Close()
			bodySeeker = bytes.NewReader(bodyBytes)
		}
		// Ensure we're at the start of the seekable body
		_, err = bodySeeker.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bodySeeker)
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
		if bodySeeker != nil {
			_, err = bodySeeker.Seek(0, io.SeekStart)
			if err != nil {
				return nil, err
			}
			req.Body = io.NopCloser(bodySeeker)
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

		if bodySeeker != nil {
			_, err = bodySeeker.Seek(0, io.SeekStart)
			if err != nil {
				return nil, err
			}
			req.Body = io.NopCloser(bodySeeker)
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

		if bodySeeker != nil {
			_, err = bodySeeker.Seek(0, io.SeekStart)
			if err != nil {
				return nil, err
			}
			req.Body = io.NopCloser(bodySeeker)
		}

		return rt.RoundTrip(req)
	}

	return res, err
}
