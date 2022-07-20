package ntlmssp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

const micFieldOffset = 72
const micFieldLength = 16

type authenticateMessage struct {
	LmChallengeResponse []byte
	NtChallengeResponse []byte

	TargetName string
	UserName   string

	NegotiateFlags negotiateFlags
	Version
}

type MIC [16]byte

type authenticateMessageFields struct {
	messageHeader
	LmChallengeResponse varField
	NtChallengeResponse varField
	TargetName          varField
	UserName            varField
	Workstation         varField
	_                   [8]byte
	NegotiateFlags      negotiateFlags
	Version
	MIC
}

func (m authenticateMessage) MarshalBinary() ([]byte, error) {
	if !m.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEUNICODE) {
		return nil, errors.New("Only unicode is supported")
	}

	target, user := toUnicode(m.TargetName), toUnicode(m.UserName)
	workstation := toUnicode("")

	ptr := binary.Size(&authenticateMessageFields{})
	f := authenticateMessageFields{
		messageHeader:       newMessageHeader(3),
		LmChallengeResponse: newVarField(&ptr, len(m.LmChallengeResponse)),
		NtChallengeResponse: newVarField(&ptr, len(m.NtChallengeResponse)),
		TargetName:          newVarField(&ptr, len(target)),
		UserName:            newVarField(&ptr, len(user)),
		Workstation:         newVarField(&ptr, len(workstation)),
		NegotiateFlags:      m.NegotiateFlags,
		Version:             m.Version,
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
	if err := binary.Write(&b, binary.LittleEndian, &target); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &user); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &workstation); err != nil {
		return nil, err
	}

	authenticateMessageData := b.Bytes()

	return authenticateMessageData, nil
}

//ProcessChallenge crafts an AUTHENTICATE message in response to the CHALLENGE message
//that was received from the server
func ProcessChallenge(negotiateMessageData, challengeMessageData []byte, user, password, domain string) ([]byte, error) {
	if user == "" && password == "" {
		return nil, errors.New("Anonymous authentication not supported")
	}

	var cm challengeMessage
	if err := cm.UnmarshalBinary(challengeMessageData); err != nil {
		return nil, err
	}

	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATELMKEY) {
		return nil, errors.New("Only NTLM v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
	}
	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) {
		return nil, errors.New("Key exchange requested but not supported (NTLMSSP_NEGOTIATE_KEY_EXCH)")
	}

	am := authenticateMessage{
		UserName:       user,
		TargetName:     domain,
		NegotiateFlags: cm.NegotiateFlags,
	}

	timestamp := cm.TargetInfo[avIDMsvAvTimestamp]
	if timestamp == nil { // no time sent, take current time
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}

	clientChallenge := make([]byte, 8)
	rand.Reader.Read(clientChallenge)

	ntlmV2Hash := getNtlmV2Hash(password, user, cm.TargetName)

	NtChallengeResponse, sessionKey := computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)
	am.NtChallengeResponse = NtChallengeResponse

	if cm.TargetInfoRaw == nil {
		am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
			cm.ServerChallenge[:], clientChallenge)
	} else {
		am.LmChallengeResponse = make([]byte, 24)
	}

	authenticateMessageData, err := am.MarshalBinary()
	if err != nil {
		return nil, err
	}

	mic := computeMIC(sessionKey, negotiateMessageData, challengeMessageData, authenticateMessageData)
	copy(authenticateMessageData[micFieldOffset:micFieldOffset+micFieldLength], mic)

	return authenticateMessageData, nil
}
