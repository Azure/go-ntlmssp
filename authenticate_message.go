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

	// only set if negotiateFlag_NTLMSSP_NEGOTIATE_KEY_EXCH
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
		SessionKey:          newVarField(&ptr, len(m.EncryptedRandomSessionKey)),
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
}

// newAuthenticateMessageInternal is the shared implementation for building an AUTHENTICATE message.
// It returns the serialized message bytes and the exported session key (non-nil only when
// NTLMSSP_NEGOTIATE_KEY_EXCH was negotiated). Public callers that do not need the session key
// should use [NewAuthenticateMessage].
func newAuthenticateMessageInternal(challenge []byte, username, password string, options *AuthenticateMessageOptions) ([]byte, []byte, error) {
	if username == "" && password == "" {
		return nil, nil, errors.New("anonymous authentication not supported")
	}

	user, domain := splitNameForAuth(username)

	var ntlmV2Hash []byte
	if options != nil && options.PasswordHashed {
		hashParts := strings.Split(password, ":")
		if len(hashParts) > 1 {
			password = hashParts[1]
		}
		hashBytes, err := hex.DecodeString(password)
		if err != nil {
			return nil, nil, err
		}
		ntlmV2Hash = getNtlmV2Hashed(hashBytes, user, domain)
	} else {
		ntlmV2Hash = getNtlmV2Hash(password, user, domain)
	}

	var workstation string
	if options != nil {
		workstation = options.WorkstationName
	}

	return buildAuthenticateMessageFromHash(challenge, username, ntlmV2Hash, workstation)
}

// buildAuthenticateMessageFromHash builds an AUTHENTICATE message using a pre-computed NTLMv2
// hash instead of a raw password. This allows callers to cache the hash and avoid storing
// the plain-text password in memory across authentication attempts.
func buildAuthenticateMessageFromHash(challenge []byte, username string, ntlmV2Hash []byte, workstation string) ([]byte, []byte, error) {
	var cm challengeMessage
	if err := cm.UnmarshalBinary(challenge); err != nil {
		return nil, nil, err
	}

	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATELMKEY) {
		return nil, nil, errors.New("only NTLM v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
	}

	am := authenicateMessage{
		NegotiateFlags: cm.NegotiateFlags,
	}
	am.UserName, am.DomainName = splitNameForAuth(username)
	am.Workstation = workstation

	timestamp := cm.TargetInfo[avIDMsvAvTimestamp]
	if timestamp == nil { // no time sent, take current time
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}

	clientChallenge := make([]byte, 8)
	if _, err := rand.Reader.Read(clientChallenge); err != nil {
		return nil, nil, err
	}

	am.NtChallengeResponse = computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)

	if cm.TargetInfoRaw == nil ||
		cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) {
		am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
			cm.ServerChallenge[:], clientChallenge)
	}

	var exportedSessionKey []byte
	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) {
		if len(am.NtChallengeResponse) < 16 {
			return nil, nil, errors.New("invalid NTLMv2 challenge response: missing NTProofStr")
		}
		userSessionKey := hmacMd5(ntlmV2Hash, am.NtChallengeResponse[:16])

		cipher, err := rc4.NewCipher(userSessionKey)
		if err != nil {
			return nil, nil, err
		}

		exportedSessionKey = []byte(rand.Text()[:16])
		encryptedSessionKey := make([]byte, 16)
		cipher.XORKeyStream(encryptedSessionKey, exportedSessionKey)
		am.EncryptedRandomSessionKey = encryptedSessionKey
	}

	authBytes, err := am.MarshalBinary()
	return authBytes, exportedSessionKey, err
}

// NewAuthenticateMessage creates a new AUTHENTICATE message in response to the CHALLENGE message that was received from the server.
// The options parameter allows specifying additional settings for the message, it can be nil to use defaults.
func NewAuthenticateMessage(challenge []byte, username, password string, options *AuthenticateMessageOptions) ([]byte, error) {
	authBytes, _, err := newAuthenticateMessageInternal(challenge, username, password, options)
	return authBytes, err
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
