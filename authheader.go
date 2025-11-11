// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"encoding/base64"
	"net/http"
	"strings"
)

var schemaPreference = [...]string{"NTLM", "Negotiate", "Basic"}

type authheader struct {
	schema string
	data   string
}

// newAuthHeader extracts the authheader from the provided HTTP headers.
// It selects the most preferred authentication scheme.
// If no supported scheme is found, it returns an empty authheader.
func newAuthHeader(req http.Header) authheader {
	preferred := -1
	for _, s := range req.Values("Www-Authenticate") {
		for j, schema := range schemaPreference {
			if s == schema || strings.HasPrefix(s, schema+" ") {
				if preferred == -1 || j < preferred {
					preferred = j
				}
			}
		}
	}
	if preferred == -1 {
		return authheader{}
	}
	schema, data, _ := strings.Cut(schemaPreference[preferred], " ")
	return authheader{
		schema: schema,
		data:   data,
	}
}

// isNTLM returns true if the authheader schema is NTLM or Negotiate.
func (h authheader) isNTLM() bool {
	return h.schema == "NTLM" || h.schema == "Negotiate"
}

// token extracts and decodes the base64 token from the authheader.
// It returns nil if the schema is not NTLM or Negotiate.
func (h authheader) token() ([]byte, error) {
	if !h.isNTLM() {
		// Schema not supported for token extraction
		return nil, nil
	}
	// RFC4559 4.2 - The token is a base64-encoded value
	return base64.StdEncoding.DecodeString(h.data)
}
