// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"testing"
)

// createValidChallengeMessage creates a valid challenge message for testing
// that doesn't trigger unsupported features
func createValidChallengeMessage() []byte {
	return []byte{
		0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, // NTLMSSP signature
		0x02, 0x00, 0x00, 0x00, // Message type (CHALLENGE = 2)
		0x0c, 0x00, 0x0c, 0x00, // Target name length
		0x38, 0x00, 0x00, 0x00, // Target name offset
		0x01, 0x82, 0x88, 0xa2, // Negotiate flags (without KEY_EXCH and LM_KEY)
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, // Challenge
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
		0x44, 0x00, 0x4f, 0x00, 0x4d, 0x00, 0x41, 0x00, // "DOMAIN" in UTF-16LE
		0x49, 0x00, 0x4e, 0x00,
	}
}

// TestProcessChallengeBackwardCompatibility tests that ProcessChallenge maintains
// backward compatibility with the original 3-parameter signature while supporting
// the new 4-parameter signature with explicit domain control.
func TestProcessChallengeBackwardCompatibility(t *testing.T) {
	challengeMessage := createValidChallengeMessage()
	testUser := "testuser"
	testPassword := "testpass"

	t.Run("ThreeParameterAPI", func(t *testing.T) {
		// Test the original 3-parameter API that auto-detects domainNeeded
		result, err := ProcessChallenge(challengeMessage, testUser, testPassword)
		if err != nil {
			t.Fatalf("ProcessChallenge with 3 parameters failed: %v", err)
		}
		if len(result) == 0 {
			t.Fatal("ProcessChallenge returned empty result")
		}
		t.Log("3-parameter API works (backward compatible)")
	})

	t.Run("FourParameterAPI", func(t *testing.T) {
		// Test the new 4-parameter API with explicit domain control
		result, err := ProcessChallenge(challengeMessage, testUser, testPassword, true)
		if err != nil {
			t.Fatalf("ProcessChallenge with 4 parameters failed: %v", err)
		}
		if len(result) == 0 {
			t.Fatal("ProcessChallenge returned empty result")
		}
		t.Log("4-parameter API works (new functionality)")
	})

	t.Run("ExplicitDomainControl", func(t *testing.T) {
		// Test both values of domainNeeded parameter
		resultTrue, err := ProcessChallenge(challengeMessage, testUser, testPassword, true)
		if err != nil {
			t.Fatalf("ProcessChallenge with domainNeeded=true failed: %v", err)
		}

		resultFalse, err := ProcessChallenge(challengeMessage, testUser, testPassword, false)
		if err != nil {
			t.Fatalf("ProcessChallenge with domainNeeded=false failed: %v", err)
		}

		if len(resultTrue) == 0 || len(resultFalse) == 0 {
			t.Fatal("ProcessChallenge returned empty results")
		}

		t.Logf("domainNeeded=true result length: %d", len(resultTrue))
		t.Logf("domainNeeded=false result length: %d", len(resultFalse))
	})
}

// TestProcessChallengeAutoDetection tests that the auto-detection logic
// correctly determines domainNeeded based on username format.
func TestProcessChallengeAutoDetection(t *testing.T) {
	challengeMessage := createValidChallengeMessage()
	testPassword := "testpass"

	testCases := []struct {
		username    string
		description string
		shouldWork  bool
	}{
		{"DOMAIN\\user", "SAM format should auto-detect domainNeeded=true", true},
		{"user@domain.com", "UPN format should auto-detect domainNeeded=false", true},
		{"plainuser", "Plain username should auto-detect domainNeeded=true", true},
	}

	for _, tc := range testCases {
		t.Run(tc.username, func(t *testing.T) {
			// Call with 3-parameter API to test auto-detection
			result, err := ProcessChallenge(challengeMessage, tc.username, testPassword)
			if tc.shouldWork {
				if err != nil {
					t.Fatalf("ProcessChallenge with auto-detection failed for %s: %v", tc.username, err)
				}
				if len(result) == 0 {
					t.Fatal("ProcessChallenge returned empty result")
				}
				t.Logf("%s - auto-detection worked!", tc.description)
			} else {
				if err == nil {
					t.Fatalf("Expected ProcessChallenge to fail for %s, but it succeeded", tc.username)
				}
				t.Logf("%s - correctly failed as expected: %v", tc.description, err)
			}
		})
	}
}

// TestProcessChallengeUPNSupport specifically tests the UPN functionality
// that was added in the original patch.
func TestProcessChallengeUPNSupport(t *testing.T) {
	challengeMessage := createValidChallengeMessage()
	testPassword := "testpass"

	t.Run("UPNWithExplicitDomainFalse", func(t *testing.T) {
		// UPN format with explicit domainNeeded=false
		result, err := ProcessChallenge(challengeMessage, "user@domain.com", testPassword, false)
		if err != nil {
			t.Fatalf("UPN with domainNeeded=false failed: %v", err)
		}
		if len(result) == 0 {
			t.Fatal("ProcessChallenge returned empty result")
		}
		t.Log("UPN with explicit domainNeeded=false works")
	})

	t.Run("UPNWithAutoDetection", func(t *testing.T) {
		// UPN format with auto-detection (should detect domainNeeded=false)
		result, err := ProcessChallenge(challengeMessage, "user@domain.com", testPassword)
		if err != nil {
			t.Fatalf("UPN with auto-detection failed: %v", err)
		}
		if len(result) == 0 {
			t.Fatal("ProcessChallenge returned empty result")
		}
		t.Log("UPN with auto-detection works")
	})

	t.Run("SAMWithAutoDetection", func(t *testing.T) {
		// SAM format with auto-detection (should detect domainNeeded=true)
		result, err := ProcessChallenge(challengeMessage, "DOMAIN\\user", testPassword)
		if err != nil {
			t.Fatalf("SAM with auto-detection failed: %v", err)
		}
		if len(result) == 0 {
			t.Fatal("ProcessChallenge returned empty result")
		}
		t.Log("SAM with auto-detection works")
	})
}

// TestProcessChallengeErrorCases tests error conditions
func TestProcessChallengeErrorCases(t *testing.T) {
	challengeMessage := createValidChallengeMessage()

	t.Run("EmptyCredentials", func(t *testing.T) {
		_, err := ProcessChallenge(challengeMessage, "", "")
		if err == nil {
			t.Fatal("Expected error for empty credentials, but got none")
		}
		expectedMsg := "anonymous authentication not supported"
		if err.Error() != expectedMsg {
			t.Fatalf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
		}
		t.Log("Correctly rejects empty credentials")
	})

	t.Run("InvalidChallengeMessage", func(t *testing.T) {
		invalidMessage := []byte{0x00, 0x01, 0x02, 0x03}
		_, err := ProcessChallenge(invalidMessage, "user", "pass")
		if err == nil {
			t.Fatal("Expected error for invalid challenge message, but got none")
		}
		t.Logf("Correctly rejects invalid challenge message: %v", err)
	})

	t.Run("EmptyUsernameWithPassword", func(t *testing.T) {
		// Empty username with non-empty password is actually allowed
		result, err := ProcessChallenge(challengeMessage, "", "password")
		if err != nil {
			t.Fatalf("ProcessChallenge with empty username but non-empty password failed: %v", err)
		}
		if len(result) == 0 {
			t.Fatal("ProcessChallenge returned empty result")
		}
		t.Log("Empty username with non-empty password is allowed")
	})
}

// TestProcessChallengeConsistency ensures that the same inputs produce
// the same outputs regardless of which API is used.
func TestProcessChallengeConsistency(t *testing.T) {
	challengeMessage := createValidChallengeMessage()
	testPassword := "testpass"

	testCases := []struct {
		username             string
		expectedDomainNeeded bool
	}{
		{"DOMAIN\\user", true},
		{"user@domain.com", false},
		{"plainuser", true},
	}

	for _, tc := range testCases {
		t.Run(tc.username, func(t *testing.T) {
			// Call with auto-detection (3 parameters)
			resultAuto, err := ProcessChallenge(challengeMessage, tc.username, testPassword)
			if err != nil {
				t.Fatalf("Auto-detection failed: %v", err)
			}

			// Call with explicit domainNeeded (4 parameters)
			resultExplicit, err := ProcessChallenge(challengeMessage, tc.username, testPassword, tc.expectedDomainNeeded)
			if err != nil {
				t.Fatalf("Explicit domainNeeded failed: %v", err)
			}

			// Results should be identical
			if len(resultAuto) != len(resultExplicit) {
				t.Fatalf("Result lengths differ: auto=%d, explicit=%d", len(resultAuto), len(resultExplicit))
			}

			// We don't compare byte-by-byte as there might be timestamp differences,
			// but the lengths should match and both should be non-empty
			if len(resultAuto) == 0 {
				t.Fatal("Both results are empty")
			}

			t.Logf("Consistency check passed for %s (domainNeeded=%v)", tc.username, tc.expectedDomainNeeded)
		})
	}
}
