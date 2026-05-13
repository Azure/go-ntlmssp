// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"context"
	"net/http"
	"os"
	"testing"
)

// TestE2E tests NTLM authentication against a real IIS server with Windows Authentication enabled
func TestE2E_Failure(t *testing.T) {
	// Get test configuration from environment variables
	testURL := os.Getenv("NTLM_TEST_URL")
	if testURL == "" {
		testURL = "http://localhost:8080/"
	}

	if os.Getenv("NTLM_TEST_PASSWORD") == "" {
		t.Skip("No password available")
	}

	t.Run("AuthenticationFailure", func(t *testing.T) {
		client := &http.Client{
			Transport: Negotiator{
				RoundTripper: &http.Transport{},
			},
		}

		req, err := http.NewRequestWithContext(t.Context(), "GET", testURL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		// Use wrong password
		req.SetBasicAuth(username, "wrongpassword")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to reach server: %v", err)
		}
		defer resp.Body.Close()

		// Should get 401 Unauthorized
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			// Expected
		default:
			t.Errorf("Expected 401 Unauthorized with wrong credentials, got %d", resp.StatusCode)
		}
	})

	t.Run("ServerAccessibility", func(t *testing.T) {
		client := &http.Client{}

		req, err := http.NewRequestWithContext(t.Context(), "GET", testURL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to reach server: %v", err)
		}
		defer resp.Body.Close()

		// Should get 401 Unauthorized (server requires auth)
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			// Expected
		default:
			t.Errorf("Unexpected status without auth: %d (expected 401)", resp.StatusCode)
		}
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		client := &http.Client{
			Transport: Negotiator{
				RoundTripper: &http.Transport{},
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel() // Cancel immediately

		req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		req.SetBasicAuth(username, password)

		resp, err := client.Do(req)
		if err == nil {
			// If the request somehow succeeded despite the short timeout, close the body
			defer resp.Body.Close()
			t.Error("Expected context cancellation error, but request succeeded")
		}
	})
}

// TestNTLM_E2E_DomainFormats tests different username formats with real NTLM server
func TestE2E_Success(t *testing.T) {
	testURL := os.Getenv("NTLM_TEST_URL")
	if testURL == "" {
		testURL = "http://localhost:8080/"
	}

	username := os.Getenv("NTLM_TEST_USER")
	if username == "" {
		username = os.Getenv("USERNAME")
		if username == "" {
			t.Skip("No username available for domain format test")
		}
	}

	password := os.Getenv("NTLM_TEST_PASSWORD")
	if password == "" {
		t.Skip("No password available for domain format test")
	}

	domain := os.Getenv("NTLM_TEST_DOMAIN")
	if domain == "" {
		domain = os.Getenv("USERDOMAIN")
	}

	computerName := os.Getenv("COMPUTERNAME")
	if computerName == "" {
		computerName = "localhost"
	}

	t.Logf("Testing domain formats against: %s", testURL)

	names := []string{
		username,
		".\\" + username,
		computerName + "\\" + username,
		domain + "\\" + username,
		// username + "@" + domain, // Disabled: still need to figure out how to set up an account for this
	}

	for _, username := range names {
		t.Run(username, func(t *testing.T) {
			client := &http.Client{
				Transport: Negotiator{
					RoundTripper: &http.Transport{},
				},
			}

			req, err := http.NewRequestWithContext(t.Context(), "GET", testURL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			req.SetBasicAuth(username, password)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Authentication failed with error: %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected status 200, got %d with format: %s", resp.StatusCode, username)
			}
		})
	}
}
