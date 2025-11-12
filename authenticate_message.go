// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type authenicateMessage struct {
	LmChallengeResponse []byte
	NtChallengeResponse []byte

	DomainName string
	UserName   string

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
	_                   [8]byte
	NegotiateFlags      negotiateFlags
}

func (m *authenicateMessage) MarshalBinary() ([]byte, error) {
	if !m.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEUNICODE) {
		return nil, errors.New("only unicode is supported")
	}

	domain, user := toUnicode(m.DomainName), toUnicode(m.UserName)
	workstation := toUnicode("")

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

// ProcessChallenge crafts an AUTHENTICATE message in response to the CHALLENGE message that was received from the server.
// DomainNeeded is ignored, as the function extracts the domain from the username if needed.
func ProcessChallenge(challengeMessageData []byte, username, password string, domainNeeded bool) ([]byte, error) {
	if username == "" && password == "" {
		return nil, errors.New("anonymous authentication not supported")
	}

	var cm challengeMessage
	if err := cm.UnmarshalBinary(challengeMessageData); err != nil {
		return nil, err
	}

	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATELMKEY) {
		return nil, errors.New("only NTLM v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
	}
	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) {
		return nil, errors.New("key exchange requested but not supported (NTLMSSP_NEGOTIATE_KEY_EXCH)")
	}

	am := authenicateMessage{
		NegotiateFlags: cm.NegotiateFlags,
	}
	am.UserName, am.DomainName = splitNameForAuth(username)

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

	ntlmV2Hash := getNtlmV2Hash(password, am.UserName, am.DomainName)

	am.NtChallengeResponse = computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)

	if cm.TargetInfoRaw == nil {
		am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
			cm.ServerChallenge[:], clientChallenge)
	}
	return am.MarshalBinary()
}

func ProcessChallengeWithHash(challengeMessageData []byte, username, hash string) ([]byte, error) {
	if username == "" && hash == "" {
		return nil, errors.New("anonymous authentication not supported")
	}

	var cm challengeMessage
	if err := cm.UnmarshalBinary(challengeMessageData); err != nil {
		return nil, err
	}

	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATELMKEY) {
		return nil, errors.New("only NTLM v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
	}
	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) {
		return nil, errors.New("key exchange requested but not supported (NTLMSSP_NEGOTIATE_KEY_EXCH)")
	}

	am := authenicateMessage{
		NegotiateFlags: cm.NegotiateFlags,
	}
	am.UserName, am.DomainName = splitNameForAuth(username)

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

	hashParts := strings.Split(hash, ":")
	if len(hashParts) > 1 {
		hash = hashParts[1]
	}
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}
	ntlmV2Hash := hmacMd5(hashBytes, toUnicode(strings.ToUpper(username)+am.DomainName))

	am.NtChallengeResponse = computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)

	if cm.TargetInfoRaw == nil {
		am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
			cm.ServerChallenge[:], clientChallenge)
	}
	return am.MarshalBinary()
}
