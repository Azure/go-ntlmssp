// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type authenicateMessage struct {
	LmChallengeResponse []byte
	NtChallengeResponse []byte

	DomainName  string
	UserName    string
	Workstation string

	// only set if NTLMSSP_NEGOTIATE_KEY_EXCH is negotiated together with SIGN or SEAL
	EncryptedRandomSessionKey []byte

	NegotiateFlags negotiateFlags

	MIC []byte
}

type authenticateMessageFields struct {
	messageHeader
	LmChallengeResponse varField
	NtChallengeResponse varField
	DomainName          varField
	UserName            varField
	Workstation         varField
	SessionKey          varField
	NegotiateFlags      negotiateFlags
}

func (m *authenicateMessage) MarshalBinary() ([]byte, error) {
	if !m.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEUNICODE) {
		return nil, errors.New("only unicode is supported")
	}

	domain, user := toUnicode(m.DomainName), toUnicode(m.UserName)
	workstation := toUnicode(m.Workstation)

	ptr := binary.Size(&authenticateMessageFields{})
	f := authenticateMessageFields{
		messageHeader:       newMessageHeader(3),
		NegotiateFlags:      m.NegotiateFlags,
		LmChallengeResponse: newVarField(&ptr, len(m.LmChallengeResponse)),
		NtChallengeResponse: newVarField(&ptr, len(m.NtChallengeResponse)),
		DomainName:          newVarField(&ptr, len(domain)),
		UserName:            newVarField(&ptr, len(user)),
		Workstation:         newVarField(&ptr, len(workstation)),
	}
	if len(m.EncryptedRandomSessionKey) > 0 {
		f.SessionKey = newVarField(&ptr, len(m.EncryptedRandomSessionKey))
	}

	f.NegotiateFlags.Unset(negotiateFlagNTLMSSPNEGOTIATEVERSION)

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &f); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &m.LmChallengeResponse); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &m.NtChallengeResponse); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &domain); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &user); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &workstation); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &m.EncryptedRandomSessionKey); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func splitNameForAuth(username string) (user, domain string) {
	if strings.Contains(username, "\\") {
		ucomponents := strings.SplitN(username, "\\", 2)
		domain = ucomponents[0]
		user = ucomponents[1]
	} else if strings.Contains(username, "@") {
		user = username
	} else {
		user = username
	}
	return user, domain
}

// AuthenticateMessageOptions contains optional parameters for the Authenticate message.
type AuthenticateMessageOptions struct {
	WorkstationName string

	// PasswordHashed indicates whether the provided password is already hashed.
	// If true, the password is expected to be in hexadecimal format.
	PasswordHashed bool

	// ExportedSessionKey, if non-nil, receives the exported session key
	// (MS-NLMP 3.1.5.1.2). Callers that need to sign or seal subsequent
	// messages (e.g. WinRM encrypted transport) should set this field. The
	// key is written before [NewAuthenticateMessage] returns, so callers can
	// use it to seal the request body that travels in the same HTTP request
	// as the AUTHENTICATE token.
	//
	// When NTLMSSP_NEGOTIATE_KEY_EXCH is negotiated together with SIGN or
	// SEAL, this is a random key sent to the server encrypted with the
	// KeyExchangeKey. Otherwise it is the KeyExchangeKey itself, and no
	// encrypted key is sent on the wire.
	ExportedSessionKey *[]byte

	// RequireSealing, if true, causes NewAuthenticateMessage to fail unless the server's
	// CHALLENGE message negotiated NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_SIGN,
	// NTLMSSP_NEGOTIATE_SEAL, and NTLMSSP_NEGOTIATE_128.
	//
	// Per MS-NLMP 3.1.5.1.2, the client must enforce its own security policy against what
	// the server actually selected, not just what the client requested in the NEGOTIATE
	// message: a server is free to clear any of these bits in its response. Without this
	// check, a caller that needs a sealed 128-bit session (e.g. WinRM encrypted transport)
	// could silently proceed with a downgraded session instead. Set this whenever
	// [NegotiateMessageOptions.RequestSealing] was set on the NEGOTIATE message.
	RequireSealing bool
}

// NewAuthenticateMessage creates a new AUTHENTICATE message in response to the CHALLENGE message
// that was received from the server. The options parameter allows specifying additional settings
// for the message; it can be nil to use defaults.
//
// To obtain the exported session key (needed for signing or sealing subsequent messages, e.g.
// WinRM encrypted transport), set [AuthenticateMessageOptions.ExportedSessionKey] to a non-nil
// pointer before calling. The pointed-to key is reset to nil at the start of the call and is
// always populated before the function returns (see [AuthenticateMessageOptions.ExportedSessionKey]
// for how the key is derived).
func NewAuthenticateMessage(challenge []byte, username, password string, options *AuthenticateMessageOptions) ([]byte, error) {
	if options != nil && options.ExportedSessionKey != nil {
		*options.ExportedSessionKey = nil
	}

	if username == "" && password == "" {
		return nil, errors.New("anonymous authentication not supported")
	}

	var cm challengeMessage
	if err := cm.UnmarshalBinary(challenge); err != nil {
		return nil, err
	}

	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATELMKEY) {
		return nil, errors.New("only NTLM v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
	}

	if options != nil && options.RequireSealing {
		var missing []string
		for _, f := range []struct {
			flag negotiateFlags
			name string
		}{
			{negotiateFlagNTLMSSPNEGOTIATEKEYEXCH, "NTLMSSP_NEGOTIATE_KEY_EXCH"},
			{negotiateFlagNTLMSSPNEGOTIATESIGN, "NTLMSSP_NEGOTIATE_SIGN"},
			{negotiateFlagNTLMSSPNEGOTIATESEAL, "NTLMSSP_NEGOTIATE_SEAL"},
			{negotiateFlagNTLMSSPNEGOTIATE128, "NTLMSSP_NEGOTIATE_128"},
		} {
			if !cm.NegotiateFlags.Has(f.flag) {
				missing = append(missing, f.name)
			}
		}
		if len(missing) > 0 {
			return nil, errors.New("server did not negotiate required sealing flags: " + strings.Join(missing, ", "))
		}
	}

	am := authenicateMessage{
		NegotiateFlags: cm.NegotiateFlags,
	}
	am.UserName, am.DomainName = splitNameForAuth(username)
	if options != nil {
		am.Workstation = options.WorkstationName
	}

	timestamp := cm.TargetInfo[avIDMsvAvTimestamp]
	if timestamp == nil { // no time sent, take current time
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}

	clientChallenge := make([]byte, 8)
	if _, err := rand.Reader.Read(clientChallenge); err != nil {
		return nil, err
	}

	var ntlmV2Hash []byte
	if options != nil && options.PasswordHashed {
		hashParts := strings.Split(password, ":")
		if len(hashParts) > 1 {
			password = hashParts[1]
		}
		hashBytes, err := hex.DecodeString(password)
		if err != nil {
			return nil, err
		}
		ntlmV2Hash = getNtlmV2Hashed(hashBytes, am.UserName, am.DomainName)
	} else {
		ntlmV2Hash = getNtlmV2Hash(password, am.UserName, am.DomainName)
	}

	am.NtChallengeResponse = computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)

	if cm.TargetInfoRaw == nil {
		am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
			cm.ServerChallenge[:], clientChallenge)
	} else {
		// MS-NLMP 3.1.5.1.2: when TargetInfo is present (e.g. carrying a timestamp),
		// the client SHOULD send Z(24) instead of a real, password-derived LM response.
		am.LmChallengeResponse = make([]byte, 24)
	}

	if len(am.NtChallengeResponse) < 16 {
		return nil, errors.New("invalid NTLMv2 challenge response: missing NTProofStr")
	}
	// KeyExchangeKey is the NTLMv2 session base key (MS-NLMP 3.1.5.1.2), independent
	// of whether KEY_EXCH is negotiated.
	keyExchangeKey := hmacMd5(ntlmV2Hash, am.NtChallengeResponse[:16])

	signOrSeal := cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATESIGN) ||
		cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATESEAL)

	var exportedSessionKey []byte
	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) && signOrSeal {
		exportedSessionKey = make([]byte, 16)
		if _, err := rand.Read(exportedSessionKey); err != nil {
			return nil, err
		}

		cipher, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return nil, err
		}
		encryptedSessionKey := make([]byte, 16)
		cipher.XORKeyStream(encryptedSessionKey, exportedSessionKey)
		am.EncryptedRandomSessionKey = encryptedSessionKey
	} else {
		// No KEY_EXCH, or no SIGN/SEAL negotiated: the exported session key is the
		// KeyExchangeKey itself, and no encrypted key is sent to the server.
		exportedSessionKey = keyExchangeKey
	}

	amBytes, err := am.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if options != nil && options.ExportedSessionKey != nil {
		*options.ExportedSessionKey = exportedSessionKey
	}

	return amBytes, nil
}

// ProcessChallenge crafts an AUTHENTICATE message in response to the CHALLENGE message that was received from the server.
// DomainNeeded is ignored, as the function extracts the domain from the username if needed.
//
// Deprecated: Use [NewAuthenticateMessage] instead.
//
//go:fix inline
func ProcessChallenge(challengeMessageData []byte, username, password string, domainNeeded bool) ([]byte, error) {
	return NewAuthenticateMessage(challengeMessageData, username, password, nil)
}

// ProcessChallengeWithHash is like ProcessChallenge but expects the password to be already hashed.
// The hash should be provided in hexadecimal format.
//
// Deprecated: Use [NewAuthenticateMessage] with [AuthenticateMessageOptions.PasswordHashed] instead.
//
//go:fix inline
func ProcessChallengeWithHash(challengeMessageData []byte, username, hash string) ([]byte, error) {
	return NewAuthenticateMessage(challengeMessageData, username, hash, &AuthenticateMessageOptions{
		PasswordHashed: true,
	})
}
