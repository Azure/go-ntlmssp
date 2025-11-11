// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This example demonstrates HTTPS authentication with custom TLS configuration.
// Useful for self-signed certificates or custom CA certificates.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/Azure/go-ntlmssp"
)

func main() {
	// Configuration
	url := "https://ntlm-protected-server.example.com/resource"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"
	caCertFile := "/path/to/ca-cert.pem" // Optional: path to CA certificate

	// Create TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Option 1: Load custom CA certificate (for self-signed certs)
	if caCertFile != "" {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			log.Printf("Warning: Failed to read CA certificate: %v", err)
		} else {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				tlsConfig.RootCAs = caCertPool
				log.Println("Custom CA certificate loaded")
			}
		}
	}

	// Option 2: Skip certificate verification (NOT recommended for production!)
	// Uncomment the following line only for testing with self-signed certificates
	// tlsConfig.InsecureSkipVerify = true

	// Create an HTTP client with NTLM authentication and custom TLS config
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: tlsConfig,
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
