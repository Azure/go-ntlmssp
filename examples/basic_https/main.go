// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This example demonstrates HTTPS authentication using NTLM.
// The library works seamlessly with HTTPS - simply use https:// URLs.
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/Azure/go-ntlmssp"
)

func main() {
	// Configuration
	url := "https://ntlm-protected-server.example.com/resource"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"

	// Create an HTTP client with NTLM authentication over HTTPS
	// The Transport supports standard TLS configuration
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{
					// Use default system certificate pool
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}

	// Create the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Set basic auth credentials - these will be automatically converted to NTLM
	req.SetBasicAuth(username, password)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read and display the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Response: %s\n", string(body))
}
