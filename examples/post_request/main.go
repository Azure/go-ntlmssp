// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// This example demonstrates POST requests with NTLM authentication over HTTPS.
// Shows how to send data in the request body with proper authentication.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/Azure/go-ntlmssp"
)

func main() {
	// Configuration
	url := "https://ntlm-protected-server.example.com/api/data"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"

	// Prepare request data
	data := map[string]interface{}{
		"message": "Hello from go-ntlmssp",
		"value":   42,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Create an HTTP client with NTLM authentication
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}

	// Create the POST request
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
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
