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
	})

	t.Run("no MIC without NegotiateMessage", func(t *testing.T) {
		am, err := NewAuthenticateMessage(ch, username, password, nil)
		if err != nil {
			t.Fatalf("NewAuthenticateMessage failed: %v", err)
		}
		var f authenticateMessageFields
		if err := binary.Read(bytes.NewReader(am), binary.LittleEndian, &f); err != nil {
			t.Fatalf("failed to parse AUTHENTICATE message: %v", err)
		}
		if f.LmChallengeResponse.BufferOffset != 72 {
			t.Fatalf("expected payload right after the Version field at 72, got %d", f.LmChallengeResponse.BufferOffset)
		}
	})
}
