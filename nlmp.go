// Package ntlmssp provides NTLM/Negotiate authentication over HTTP
//
// Protocol details from https://msdn.microsoft.com/en-us/library/cc236621.aspx,
// implementation hints from http://davenport.sourceforge.net/ntlm.html .
// This package only implements authentication, no key exchange or encryption. It
// only supports Unicode (UTF16LE) encoding of protocol strings, no OEM encoding.
// This package implements NTLMv2.
package ntlmssp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"golang.org/x/crypto/md4"
	"strings"
)

func getNtlmV2Hash(password, username, target string) []byte {
	return hmacMd5(getNtlmHash(password), toUnicode(strings.ToUpper(username)+target))
}

func getNtlmHash(password string) []byte {
	hash := md4.New()
	hash.Write(toUnicode(password))
	return hash.Sum(nil)
}

func computeNtlmV2Response(ntlmV2Hash, serverChallenge, clientChallenge, timestamp, targetInfo []byte) ([]byte, []byte) {

	buf := bytes.NewBuffer([]byte{1, 1, 0, 0, 0, 0, 0, 0})
	buf.Write(timestamp)
	buf.Write(clientChallenge)
	buf.Write([]byte{0, 0, 0, 0})
	buf.Write(targetInfo)
	buf.Write([]byte{0, 0, 0, 0})

	NTProofStr := hmacMd5(ntlmV2Hash, serverChallenge, buf.Bytes())
	sessionKey := hmacMd5(ntlmV2Hash, NTProofStr)

	return append(NTProofStr, buf.Bytes()...), sessionKey
}

func computeLmV2Response(ntlmV2Hash, serverChallenge, clientChallenge []byte) []byte {
	return append(hmacMd5(ntlmV2Hash, serverChallenge, clientChallenge), clientChallenge...)
}

func hmacMd5(key []byte, data ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, d := range data {
		mac.Write(d)
	}
	return mac.Sum(nil)
}

func md5sum(target []byte, data ...[]byte) []byte {
	h := md5.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(target)

}

func computeMIC(sessionKey []byte, messages ...[]byte) []byte {
	return hmacMd5(sessionKey, messages...)
}

type gssChannelBindingStructHeader struct {
	_           [16]byte
	tokenLength uint32
}

func computeChannelBindingHash(channelBinding []byte) ([]byte, error) {

	if channelBinding != nil {

		// Based on [MS-NLMP documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e):
		// Channel binding hash value contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct
		// ([RFC2744](https://www.ietf.org/rfc/rfc2744.txt) section 3.11). An all-zero value of the hash is used to indicate
		// absence of channel bindings.
		cbtStruct := gssChannelBindingStructHeader{
			tokenLength: uint32(len(channelBinding)),
		}

		size := binary.Size(&gssChannelBindingStructHeader{})

		buf := bytes.NewBuffer(make([]byte, 0, size+len(channelBinding)))
		if err := binary.Write(buf, binary.LittleEndian, &cbtStruct); err != nil {
			return nil, err
		}
		_, err := buf.Write(channelBinding)
		if err != nil {
			return nil, err
		}

		channelBindingHash := make([]byte, 0, 16)
		channelBindingHash = md5sum(channelBindingHash, buf.Bytes())

		return channelBindingHash, nil
	} else {
		return make([]byte, 16), nil
	}
}
