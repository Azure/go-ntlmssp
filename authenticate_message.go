package ntlmssp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const micFieldOffset = 72
const micFieldLength = 16

type authenticateMessage struct {
	LmChallengeResponse []byte
	NtChallengeResponse []byte

	TargetName string
	UserName   string

	NegotiateFlags NegotiateFlags
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
	NegotiateFlags      NegotiateFlags
	Version
	MIC
}

func (m authenticateMessage) MarshalBinary() ([]byte, error) {
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
func ProcessChallenge(negotiateMessageData, challengeMessageData []byte, user, password, domain, spn string, channelBinding []byte) ([]byte, error) {
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

	if !cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEUNICODE) {
		return nil, errors.New("Only unicode is supported")
	}

	flags := (defaultFlags & cm.NegotiateFlags) | negotiateFlagNTLMSSPNEGOTIATEEXTENDEDSESSIONSECURITY

	am := authenticateMessage{
		UserName:       user,
		TargetName:     domain,
		NegotiateFlags: flags,
	}

	targetInfo := cm.TargetInfo

	cbt, err := computeChannelBindingHash(channelBinding)
	if err != nil {
		return nil, fmt.Errorf("failed to compute channel binding token: %w", err)
	}

	targetInfo, serverTimestamp := updateTargetInfoAvPairs(targetInfo, cbt, spn)

	timestamp := getTimestamp(serverTimestamp)

	ntlmV2Hash := getNtlmV2Hash(password, am.UserName, am.TargetName)

	clientChallenge := getClientChallenge()

	targetInfoData, err := targetInfo.marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TargetInfo AvPair struct: %w", err)
	}

	NtChallengeResponse, sessionKey := computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, targetInfoData)
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

func getTimestamp(serverTimestamp []byte) []byte {
	if serverTimestamp != nil { // no time sent, take current time
		return serverTimestamp
	} else {
		// Prepares current timestamp in format specified in
		// [MS-NLMP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e)
		// A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local
		// time. This structure is always sent in the CHALLENGE_MESSAGE.
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp := make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
		return timestamp
	}
}

func getClientChallenge() []byte {
	clientChallenge := make([]byte, 8)
	rand.Reader.Read(clientChallenge)
	return clientChallenge
}

func updateTargetInfoAvPairs(targetInfo AvPairs, channelBindingHash []byte, spn string) (AvPairs, []byte) {

	serverTimestamp := targetInfo[avIDMsvAvTimestamp]

	// update AvFlags - MIC present
	{
		flags := targetInfo[avIDMsvAvFlags]
		if flags == nil {
			flags = make([]byte, 4)
			targetInfo[avIDMsvAvFlags] = flags
		}
		avFlags := AvFlags(binary.LittleEndian.Uint32(flags))
		avFlags.Set(AvFlagMICPresent)
		binary.LittleEndian.PutUint32(flags, uint32(avFlags))
	}

	// EPA support
	{
		targetInfo[avIDMsvChannelBindings] = channelBindingHash
		targetInfo[avIDMsvAvTargetName] = toUnicode(spn)
	}

	return targetInfo, serverTimestamp
}
