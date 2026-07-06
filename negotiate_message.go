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

// NegotiateMessageOptions contains optional parameters for the NEGOTIATE message.
// The zero value is valid and sends neither client domain nor workstation name.
type NegotiateMessageOptions struct {
	// Domain is the domain of the client machine.
	// Per the NTLM spec, it may be empty. When empty, no domain bytes are sent and
	// NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED is left unset.
	Domain string

	// Workstation is the name of the client machine.
	// Per the NTLM spec, it may be empty. When empty, no workstation bytes are sent and
	// NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED is left unset.
	Workstation string
}

// NewNegotiateMessage creates a new NEGOTIATE message with the flags that this package supports.
// Note that domain and workstation refer to the client machine, not the user that is authenticating.
// It is recommended to leave them empty unless you know which are their correct values.
//
// The server may ignore these values, or may use them to infer that the client if running on the
// same machine.
func NewNegotiateMessage(domain, workstation string) ([]byte, error) {
	return NewNegotiateMessageWithOptions(NegotiateMessageOptions{
		Domain:      domain,
		Workstation: workstation,
	})
}

// NewNegotiateMessageWithOptions creates a new NEGOTIATE message from the supplied options.
// Use this function when setting optional NEGOTIATE message fields. To preserve compatibility
// with existing callers, [NewNegotiateMessage] remains available for passing only the client
// domain and workstation values.
func NewNegotiateMessageWithOptions(options NegotiateMessageOptions) ([]byte, error) {
	payloadOffset := expMsgBodyLen
	flags := defaultFlags
	domain := options.Domain
	workstation := options.Workstation

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
