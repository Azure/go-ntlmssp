// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"encoding/base64"
	"net/http"
	"strings"
)

type authheader []string

func newAuthHeader(req http.Header) authheader {
	return authheader(req.Values("Www-Authenticate"))
}

func (h authheader) IsNTLM() bool {
	schema := h.Schema()
	return schema == "NTLM" || schema == "Negotiate"
}

func (h authheader) Schema() string {
	var choosen string
	isSchema := func(s, schema string) bool {
		return s == schema || strings.HasPrefix(s, schema+" ")
	}
	for _, s := range h {
		if isSchema(s, "NTLM") {
			return "NTLM"
		}
		if isSchema(s, "Negotiate") {
			choosen = "Negotiate"
		}
		if isSchema(s, "Basic") {
			if choosen == "" {
				// only choose Basic if no other schema was found
				choosen = "Basic"
			}
		}
	}
	return choosen
}

func (h authheader) GetData() ([]byte, error) {
	for _, s := range h {
		if strings.HasPrefix(s, "NTLM") || strings.HasPrefix(s, "Negotiate") || strings.HasPrefix(s, "Basic ") {
			p := strings.Split(s, " ")
			if len(p) < 2 {
				return nil, nil
			}
			return base64.StdEncoding.DecodeString(p[1])
		}
	}
	return nil, nil
}
