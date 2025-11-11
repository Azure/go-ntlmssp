// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/Azure/go-ntlmssp"
)

// Example demonstrates basic HTTP authentication using NTLM.
func Example() {
	url := "http://ntlm-protected-server.example.com/resource"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{},
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

// Example_https demonstrates HTTPS authentication using NTLM.
// The library works seamlessly with HTTPS - simply use https:// URLs.
func Example_https() {
	url := "https://ntlm-protected-server.example.com/resource"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"

	// Create an HTTP client with NTLM authentication over HTTPS
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

// Example_httpsWithCustomTLS demonstrates HTTPS authentication with custom TLS configuration.
// Useful for self-signed certificates or custom CA certificates.
func Example_httpsWithCustomTLS() {
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

// Example_postRequest demonstrates POST requests with NTLM authentication over HTTPS.
func Example_postRequest() {
	url := "https://ntlm-protected-server.example.com/api/data"
	username := "DOMAIN\\username"
	password := "your-password"

	// Prepare JSON data
	jsonData := []byte(`{"message": "Hello from go-ntlmssp", "value": 42}`)

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Response: %s\n", string(body))
}
