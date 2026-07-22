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

	// RequestSealing additionally requests NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_SIGN,
	// and NTLMSSP_NEGOTIATE_SEAL. Set this when the caller intends to sign or seal subsequent
	// messages (e.g. WinRM encrypted transport). Pair it with
	// [AuthenticateMessageOptions.ExportedSessionKey] to obtain the exported session key, and
	// with [AuthenticateMessageOptions.RequireSealing] so that a server which declines to
	// negotiate sealing causes an error instead of a silent downgrade.
	RequestSealing bool
}

// NewNegotiateMessage creates a new NEGOTIATE message with the flags that this package supports.
// Note that domain and workstation refer to the client machine, not the user that is authenticating.
// It is recommended to leave them empty unless you know which are their correct values.
//
// The server may ignore these values, or may use them to infer that the client if running on the
// same machine.
//
// If the server requires message signing or sealing (e.g. WinRM encrypted transport), use
// [NewNegotiateMessageWithOptions] instead and set [NegotiateMessageOptions.RequestSealing] along
// with [AuthenticateMessageOptions.ExportedSessionKey] and [AuthenticateMessageOptions.RequireSealing]
// when calling [NewAuthenticateMessage].
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

	if options.RequestSealing {
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
