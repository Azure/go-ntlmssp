// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"

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
// Useful for self-signed certificates or custom CA certificates.
func Example_customTLS() {
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
			}
		}
	}

	// Option 2: Skip certificate verification (NOT recommended for production!)
	// Uncomment the following line only for testing with self-signed certificates
	// tlsConfig.InsecureSkipVerify = true

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: tlsConfig,
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

