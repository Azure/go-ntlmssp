// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build e2e

package e2e

import (
	"testing"

	"github.com/Azure/go-ntlmssp"
)

// TestCompilation_E2E verifies that the e2e test package compiles correctly
// and can import the main ntlmssp package. This test runs on all platforms.
func TestCompilation_E2E(t *testing.T) {
	t.Run("ImportCheck", func(t *testing.T) {
		// Verify we can create a basic negotiate message
		_, err := ntlmssp.NewNegotiateMessage("testdomain", "testworkstation")
		if err != nil {
			t.Fatalf("Failed to create negotiate message: %v", err)
		}
		t.Log("Successfully imported ntlmssp and created negotiate message")
	})

	t.Run("GetDomainCheck", func(t *testing.T) {
		// Test the GetDomain function with different formats
		testCases := []struct {
			input          string
			expectedUser   string
			expectedDomain string
			expectedNeeded bool
		}{
			{"DOMAIN\\user", "user", "DOMAIN", true},
			{"user@domain.com", "user@domain.com", "", false},
			{"plainuser", "plainuser", "", true},
		}

		for _, tc := range testCases {
			user, domain, needed := ntlmssp.GetDomain(tc.input)
			if user != tc.expectedUser {
				t.Errorf("GetDomain(%s): expected user %s, got %s", tc.input, tc.expectedUser, user)
			}
			if domain != tc.expectedDomain {
				t.Errorf("GetDomain(%s): expected domain %s, got %s", tc.input, tc.expectedDomain, domain)
			}
			if needed != tc.expectedNeeded {
				t.Errorf("GetDomain(%s): expected domainNeeded %v, got %v", tc.input, tc.expectedNeeded, needed)
			}
		}
		t.Log("GetDomain function works correctly")
	})

	t.Run("NegotiatorCreation", func(t *testing.T) {
		// Verify we can create a Negotiator
		negotiator := ntlmssp.Negotiator{}
		if negotiator.RoundTripper == nil {
			t.Log("Negotiator created (RoundTripper is nil as expected)")
		}
	})
}
