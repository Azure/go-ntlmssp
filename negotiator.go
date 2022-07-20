package ntlmssp

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// GetDomain : parse domain name from based on slashes in the input
func GetDomain(user string) (string, string) {
	domain := ""

	if strings.Contains(user, "\\") {
		ucomponents := strings.SplitN(user, "\\", 2)
		domain = ucomponents[0]
		user = ucomponents[1]
	}
	return user, domain
}

//Negotiator is a http.Roundtripper decorator that automatically
//converts basic authentication to NTLM/Negotiate authentication when appropriate.
type Negotiator struct{ http.RoundTripper }

//RoundTrip sends the request to the server, handling any authentication
//re-sends as needed.
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
	// Save request body
	body := bytes.Buffer{}
	if req.Body != nil {
		_, err = body.ReadFrom(req.Body)
		if err != nil {
			return nil, err
		}

		req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
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
		req.Header.Set("Authorization", string(reqauthBasic))
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

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
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		// recycle credentials
		u, p, err := reqauth.GetBasicCreds()
		if err != nil {
			return nil, err
		}

		// get domain from username
		u, domain := GetDomain(u)

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

		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

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
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		spn := getSpn(req.Host)

		var channelBinding []byte = nil
		if res.TLS != nil {
			channelBinding, err = makeChannelBinding(*res.TLS)
			if err != nil {
				return nil, errors.New("couldn't make TLS channel binding")
			}
		}

		// send authenticate
		authenticateMessage, err := ProcessChallenge(negotiateMessage, challengeMessage, u, p, domain, spn, channelBinding)
		if err != nil {
			return nil, err
		}
		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticateMessage))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authenticateMessage))
		}

		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		return rt.RoundTrip(req)
	}

	return res, err
}

func makeChannelBinding(state tls.ConnectionState) ([]byte, error) {

	certificate := state.PeerCertificates[0]
	prefix := []byte("tls-server-end-point:")

	if certificate == nil {
		return nil, errors.New("TLS connection is missing server certificate")
	}

	// choose the channel binding hash type
	// Use the same hash type used for the certificate signature, except for MD5 and SHA-1 which
	// use SHA256
	hashType := crypto.SHA256
	switch certificate.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		hashType = crypto.SHA512
	}

	hasher := hashType.New()
	_, _ = hasher.Write(certificate.Raw)
	data := hasher.Sum(nil)

	buf := bytes.NewBuffer(make([]byte, 0, len(prefix)+len(data)))
	buf.Write(prefix)
	buf.Write(data)

	return buf.Bytes(), nil
}

func getSpn(host string) string {
	spn := ""
	if host != "" {
		spn = "HTTP/" + strings.ToLower(host)
	}
	return spn
}
