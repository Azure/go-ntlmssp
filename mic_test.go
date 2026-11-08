// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

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

	t.Run("MIC is sent when NegotiateMessage is set", func(t *testing.T) {
		var key []byte
		am, err := NewAuthenticateMessage(ch, username, password, &AuthenticateMessageOptions{
			NegotiateMessage:   negotiate,
			ExportedSessionKey: &key,
		})
		if err != nil {
			t.Fatalf("NewAuthenticateMessage failed: %v", err)
		}

		// MIC = HMAC_MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE),
		// computed with the MIC field (offset 72) zeroed.
		zeroed := bytes.Clone(am)
		copy(zeroed[72:88], make([]byte, 16))
		if want := hmacMd5(key, negotiate, ch, zeroed); !bytes.Equal(am[72:88], want) {
			t.Fatalf("expected MIC %x, got %x", want, am[72:88])
		}

		// The NTLMv2 response must tell the server a MIC is present.
		f := parseAuthenticateFields(t, am)
		nt, err := f.NtChallengeResponse.ReadFrom(am)
		if err != nil {
			t.Fatalf("failed to read NtChallengeResponse: %v", err)
		}
		micFlag := []byte{0x06, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00} // MsvAvFlags = MIC provided
		if !bytes.Contains(nt, micFlag) {
			t.Fatalf("NTLMv2 response does not contain MsvAvFlags with the MIC-provided bit: %x", nt)
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
