// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/Azure/go-ntlmssp"
)

// Example demonstrates basic HTTPS authentication using NTLM.
// The library works the same way with HTTP - just use http:// URLs instead.
func Example() {
	url := "https://ntlm-protected-server.example.com/resource"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"

	client := &http.Client{
		Transport: ntlmssp.Negotiator{},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set basic auth credentials - these will be automatically converted to NTLM
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
}

// Example_customTLS demonstrates HTTPS authentication with custom TLS configuration.
func Example_customTLS() {
	url := "https://ntlm-protected-server.example.com/resource"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				// Disable HTTP/2 to ensure NTLM works correctly
				TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set basic auth credentials - these will be automatically converted to NTLM
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
}

