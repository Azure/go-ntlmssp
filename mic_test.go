// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// micFlagPair is an MsvAvFlags AV_PAIR with only the MIC-provided bit set.
var micFlagPair = []byte{0x06, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00}

// checkMIC verifies the MIC in am the way a server does: it derives the exported
// session key from the password (decrypting the session key under KEY_EXCH) and
// recomputes HMAC_MD5(key, NEGOTIATE || CHALLENGE || AUTHENTICATE) with the MIC zeroed.
func checkMIC(t *testing.T, negotiate, challenge, am []byte) {
	t.Helper()
	f := parseAuthenticateFields(t, am)
	nt, err := f.NtChallengeResponse.ReadFrom(am)
	if err != nil {
		t.Fatalf("failed to read NtChallengeResponse: %v", err)
	}
	if !bytes.Contains(nt, micFlagPair) {
		t.Fatalf("NTLMv2 response does not contain MsvAvFlags with the MIC-provided bit: %x", nt)
	}

	key := hmacMd5(getNtlmV2Hash(password, username, ""), nt[:16]) // KeyExchangeKey
	if f.SessionKey.Len > 0 {
		encrypted, err := f.SessionKey.ReadFrom(am)
		if err != nil {
			t.Fatalf("failed to read EncryptedRandomSessionKey: %v", err)
		}
		cipher, err := rc4.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		key = make([]byte, len(encrypted))
		cipher.XORKeyStream(key, encrypted)
	}

	zeroed := bytes.Clone(am)
	copy(zeroed[72:88], make([]byte, 16))
	if want := hmacMd5(key, negotiate, challenge, zeroed); !bytes.Equal(am[72:88], want) {
		t.Fatalf("expected MIC %x, got %x", want, am[72:88])
	}
}

// makeTestChallengeWithTimestamp builds a CHALLENGE_MESSAGE whose TargetInfo carries an
// MsvAvTimestamp, which is what makes the client send a MIC (MS-NLMP 3.1.5.1.2).
func makeTestChallengeWithTimestamp(t *testing.T, flags negotiateFlags) []byte {
	t.Helper()
	targetInfo := []byte{
		0x07, 0x00, 0x08, 0x00, 0x00, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 0x01, // MsvAvTimestamp
		0x00, 0x00, 0x00, 0x00, // MsvAvEOL
	}
	payloadOffset := binary.Size(&challengeMessageFields{})
	c := challengeMessageFields{
		messageHeader:   newMessageHeader(2),
		NegotiateFlags:  flags,
		ServerChallenge: [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		TargetInfo:      newVarField(&payloadOffset, len(targetInfo)),
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &c); err != nil {
		t.Fatalf("failed to build challenge: %v", err)
	}
	buf.Write(targetInfo)
	return buf.Bytes()
}

func parseAuthenticateFields(t *testing.T, am []byte) authenticateMessageFields {
	t.Helper()
	var f authenticateMessageFields
	if err := binary.Read(bytes.NewReader(am), binary.LittleEndian, &f); err != nil {
		t.Fatalf("failed to parse AUTHENTICATE message: %v", err)
	}
	return f
}

func TestNewAuthenticateMessage_MIC(t *testing.T) {
	flags := negotiateFlagNTLMSSPNEGOTIATEUNICODE | negotiateFlagNTLMSSPNEGOTIATENTLM
	ch := makeTestChallengeWithTimestamp(t, flags)
	negotiate, err := NewNegotiateMessageWithOptions(NegotiateMessageOptions{})
	if err != nil {
		t.Fatalf("NewNegotiateMessageWithOptions failed: %v", err)
	}

	for _, tc := range []struct {
		name  string
		flags negotiateFlags
	}{
		{"MIC is sent when NegotiateMessage is set", flags},
		// Under KEY_EXCH the MIC must use the random exported session key, not KeyExchangeKey.
		{"MIC uses the exported session key under KEY_EXCH", flags | negotiateFlagNTLMSSPNEGOTIATEKEYEXCH |
			negotiateFlagNTLMSSPNEGOTIATESIGN | negotiateFlagNTLMSSPNEGOTIATESEAL | negotiateFlagNTLMSSPNEGOTIATE128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := makeTestChallengeWithTimestamp(t, tc.flags)
			am, err := NewAuthenticateMessage(ch, username, password, &AuthenticateMessageOptions{
				NegotiateMessage: negotiate,
			})
			if err != nil {
				t.Fatalf("NewAuthenticateMessage failed: %v", err)
			}
			checkMIC(t, negotiate, ch, am)
		})
	}

	t.Run("no MIC without MsvAvTimestamp", func(t *testing.T) {
		ch := makeTestChallengeWithTargetInfo(t, flags) // TargetInfo with only MsvAvEOL
		am, err := NewAuthenticateMessage(ch, username, password, &AuthenticateMessageOptions{
			NegotiateMessage: negotiate,
		})
		if err != nil {
			t.Fatalf("NewAuthenticateMessage failed: %v", err)
		}
		f := parseAuthenticateFields(t, am)
		if f.LmChallengeResponse.BufferOffset != 72 {
			t.Fatalf("expected no MIC (payload at 72), got payload at %d", f.LmChallengeResponse.BufferOffset)
		}
		nt, err := f.NtChallengeResponse.ReadFrom(am)
		if err != nil {
			t.Fatalf("failed to read NtChallengeResponse: %v", err)
		}
		if bytes.Contains(nt, micFlagPair) {
			t.Fatalf("NTLMv2 response has the MIC-provided bit without a MIC")
		}
	})

	t.Run("no MIC without NegotiateMessage", func(t *testing.T) {
		am, err := NewAuthenticateMessage(ch, username, password, nil)
		if err != nil {
			t.Fatalf("NewAuthenticateMessage failed: %v", err)
		}
		f := parseAuthenticateFields(t, am)
		if f.LmChallengeResponse.BufferOffset != 72 {
			t.Fatalf("expected payload right after the Version field at 72, got %d", f.LmChallengeResponse.BufferOffset)
		}
	})
}

func TestNewAuthenticateMessage_Version(t *testing.T) {
	negotiate, err := NewNegotiateMessageWithOptions(NegotiateMessageOptions{})
	if err != nil {
		t.Fatalf("NewNegotiateMessageWithOptions failed: %v", err)
	}
	var defaultVersion bytes.Buffer
	if err := binary.Write(&defaultVersion, binary.LittleEndian, DefaultVersion()); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		version bool
		mic     bool
	}{
		{"VERSION, no MIC", true, false},
		{"VERSION, MIC", true, true},
		{"no VERSION, no MIC", false, false},
		{"no VERSION, MIC", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := negotiateFlagNTLMSSPNEGOTIATEUNICODE | negotiateFlagNTLMSSPNEGOTIATENTLM
			if tc.version {
				flags |= negotiateFlagNTLMSSPNEGOTIATEVERSION
			}
			opts := &AuthenticateMessageOptions{}
			if tc.mic {
				opts.NegotiateMessage = negotiate
			}
			am, err := NewAuthenticateMessage(makeTestChallengeWithTimestamp(t, flags), username, password, opts)
			if err != nil {
				t.Fatalf("NewAuthenticateMessage failed: %v", err)
			}

			// MS-NLMP 2.2.1.3: Version (bytes 64-71) is populated only when
			// NTLMSSP_NEGOTIATE_VERSION is negotiated, and is zero otherwise.
			want := make([]byte, 8)
			if tc.version {
				want = defaultVersion.Bytes()
			}
			if !bytes.Equal(am[64:72], want) {
				t.Fatalf("expected Version bytes %x, got %x", want, am[64:72])
			}
			if got := parseAuthenticateFields(t, am).NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEVERSION); got != tc.version {
				t.Fatalf("expected NTLMSSP_NEGOTIATE_VERSION set=%v, got %v", tc.version, got)
			}
		})
	}
}

func TestWithMICFlag(t *testing.T) {
	timestamp := []byte{0x07, 0x00, 0x08, 0x00, 0x00, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 0x01}
	eol := []byte{0x00, 0x00, 0x00, 0x00}
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	for _, tc := range []struct {
		name string
		in   []byte
		want []byte
	}{
		{
			"MsvAvFlags is added before MsvAvEOL when absent",
			cat(timestamp, eol),
			cat(timestamp, []byte{0x06, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00}, eol),
		},
		{
			"existing MsvAvFlags keeps its bits and is not duplicated",
			cat([]byte{0x06, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00}, timestamp, eol),
			cat([]byte{0x06, 0x00, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00}, timestamp, eol),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := withMICFlag(tc.in)
			if err != nil {
				t.Fatalf("withMICFlag failed: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("expected %x, got %x", tc.want, got)
			}
		})
	}
}

// TestNegotiatorSendsMIC checks that Negotiator computes the MIC over the exact
// NEGOTIATE message it sent, including a configured workstation and domain.
func TestNegotiatorSendsMIC(t *testing.T) {
	ch := makeTestChallengeWithTimestamp(t, negotiateFlagNTLMSSPNEGOTIATEUNICODE|negotiateFlagNTLMSSPNEGOTIATENTLM)

	for _, tc := range []struct {
		name                           string
		workstationDomain, workstation string
	}{
		{"no workstation", "", ""},
		{"workstation and domain", "TESTDOMAIN", "TESTWORKSTATION"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var negotiate, authenticate []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "NTLM ")
				if !ok {
					w.Header().Set("Www-Authenticate", "NTLM")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				msg, err := base64.StdEncoding.DecodeString(token)
				if err != nil {
					t.Errorf("failed to decode token: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if negotiate == nil {
					negotiate = msg
					w.Header().Set("Www-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(ch))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				authenticate = msg
			}))
			defer server.Close()

			client := &http.Client{Transport: Negotiator{
				WorkstationDomain: tc.workstationDomain,
				WorkstationName:   tc.workstation,
			}}
			req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.SetBasicAuth(username, password)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()
			if authenticate == nil {
				t.Fatalf("server did not receive an AUTHENTICATE message")
			}
			checkMIC(t, negotiate, ch, authenticate)
		})
	}
}

func TestNewAuthenticateMessage_RejectsOversizedNTResponse(t *testing.T) {
	// A TargetInfo that fits in the CHALLENGE but, with the MIC flag added, makes the
	// NTLMv2 response longer than its 16-bit security-buffer length allows.
	big := make([]byte, 65480)
	targetInfo := binary.LittleEndian.AppendUint16(nil, uint16(avIDMsvAvNbDomainName))
	targetInfo = binary.LittleEndian.AppendUint16(targetInfo, uint16(len(big)))
	targetInfo = append(targetInfo, big...)
	targetInfo = append(targetInfo, 0x07, 0x00, 0x08, 0x00, 0x00, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 0x01) // MsvAvTimestamp
	targetInfo = append(targetInfo, 0x00, 0x00, 0x00, 0x00)                                                 // MsvAvEOL

	payloadOffset := binary.Size(&challengeMessageFields{})
	c := challengeMessageFields{
		messageHeader:   newMessageHeader(2),
		NegotiateFlags:  negotiateFlagNTLMSSPNEGOTIATEUNICODE | negotiateFlagNTLMSSPNEGOTIATENTLM,
		ServerChallenge: [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		TargetInfo:      newVarField(&payloadOffset, len(targetInfo)),
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &c); err != nil {
		t.Fatal(err)
	}
	buf.Write(targetInfo)

	negotiate, err := NewNegotiateMessageWithOptions(NegotiateMessageOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthenticateMessage(buf.Bytes(), username, password, &AuthenticateMessageOptions{
		NegotiateMessage: negotiate,
	}); err == nil {
		t.Fatalf("expected an error for an NTLMv2 response over 65535 bytes")
	}
}
