// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

const expMsgBodyLen = 40

type negotiateMessageFields struct {
	messageHeader
	NegotiateFlags negotiateFlags

	Domain      varField
	Workstation varField

	Version
}

var defaultFlags = negotiateFlagNTLMSSPNEGOTIATETARGETINFO |
	negotiateFlagNTLMSSPNEGOTIATE56 |
	negotiateFlagNTLMSSPNEGOTIATE128 |
	negotiateFlagNTLMSSPNEGOTIATEUNICODE |
	negotiateFlagNTLMSSPNEGOTIATEEXTENDEDSESSIONSECURITY |
	negotiateFlagNTLMSSPNEGOTIATENTLM |
	negotiateFlagNTLMSSPNEGOTIATEALWAYSSIGN

var sealingFlags negotiateFlags = negotiateFlagNTLMSSPNEGOTIATEKEYEXCH |
	negotiateFlagNTLMSSPNEGOTIATESIGN |
	negotiateFlagNTLMSSPNEGOTIATESEAL

// NewNegotiateMessage creates a new NEGOTIATE message for standard authentication.
// Note that domain and workstation refer to the client machine, not the user that is authenticating.
// It is recommended to leave them empty unless you know which are their correct values.
//
// The server may ignore these values, or may use them to infer that the client if running on the
// same machine.
//
// If the server requires message signing or sealing (e.g. WinRM encrypted transport), use
// [NewSealingNegotiateMessage] instead and authenticate with [NewAuthenticateMessageWithKey].
func NewNegotiateMessage(domain, workstation string) ([]byte, error) {
	return newNegotiateMessage(domain, workstation, false)
}

// NewSealingNegotiateMessage creates a NEGOTIATE message that additionally requests
// NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_SIGN, and NTLMSSP_NEGOTIATE_SEAL.
// Use this when the caller intends to sign or seal subsequent messages (e.g. WinRM encrypted
// transport). Pair it with [NewAuthenticateMessageWithKey] to obtain the exported session key.
func NewSealingNegotiateMessage(domain, workstation string) ([]byte, error) {
	return newNegotiateMessage(domain, workstation, true)
}

func newNegotiateMessage(domain, workstation string, sealing bool) ([]byte, error) {
	payloadOffset := expMsgBodyLen
	flags := defaultFlags
	if sealing {
		flags |= sealingFlags
	}

	if domain != "" {
		flags |= negotiateFlagNTLMSSPNEGOTIATEOEMDOMAINSUPPLIED
	}

	if workstation != "" {
		flags |= negotiateFlagNTLMSSPNEGOTIATEOEMWORKSTATIONSUPPLIED
	}

	msg := negotiateMessageFields{
		messageHeader:  newMessageHeader(1),
		NegotiateFlags: flags,
		Domain:         newVarField(&payloadOffset, len(domain)),
		Workstation:    newVarField(&payloadOffset, len(workstation)),
		Version:        DefaultVersion(),
	}

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &msg); err != nil {
		return nil, err
	}
	if b.Len() != expMsgBodyLen {
		return nil, errors.New("incorrect body length")
	}

	payload := strings.ToUpper(domain + workstation)
	if _, err := b.WriteString(payload); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
