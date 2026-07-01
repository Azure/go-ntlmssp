// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"errors"
	"slices"
)

// NTLM signing/sealing key derivation magic constants (MS-NLMP §3.4.5).
const (
	clientToServerSigning = "session key to client-to-server signing key magic constant"
	clientToServerSealing = "session key to client-to-server sealing key magic constant"
	serverToClientSigning = "session key to server-to-client signing key magic constant"
	serverToClientSealing = "session key to server-to-client sealing key magic constant"
	versionMagic          = "\x01\x00\x00\x00"
)

// NewClientSignKey derives the client-to-server signing key from the exported session key (MS-NLMP §3.4.5.2).
func NewClientSignKey(sessionKey []byte) []byte {
	return newDerivedKey(sessionKey, clientToServerSigning)
}

// NewClientSealKey derives the client-to-server sealing key from the exported session key (MS-NLMP §3.4.5.3).
func NewClientSealKey(sessionKey []byte) []byte {
	return newDerivedKey(sessionKey, clientToServerSealing)
}

// NewServerSignKey derives the server-to-client signing key from the exported session key (MS-NLMP §3.4.5.2).
func NewServerSignKey(sessionKey []byte) []byte {
	return newDerivedKey(sessionKey, serverToClientSigning)
}

// NewServerSealKey derives the server-to-client sealing key from the exported session key (MS-NLMP §3.4.5.3).
func NewServerSealKey(sessionKey []byte) []byte {
	return newDerivedKey(sessionKey, serverToClientSealing)
}

// Seal encrypts plaintext using the RC4 sealing cipher and computes the
// NTLMSSP_MESSAGE_SIGNATURE for it (MS-NLMP §3.4.3, §3.4.4).
//
// cipher must be the caller's persistent client (or server) sealing cipher. Its
// internal state advances with each call, so the same cipher must be reused in
// order for every message in the session (MS-NLMP §3.4 CONNECTION mode).
// seqNum is the zero-based sequence number of this message and must increment by
// one for every message sealed with this cipher.
//
// ciphertext and signature are returned separately so the caller can frame them
// in whatever protocol envelope is appropriate (e.g. WinRM multipart/encrypted).
func Seal(cipher *rc4.Cipher, signKey []byte, seqNum uint32, plaintext []byte) (ciphertext, signature []byte) {
	seq := seqBytes(seqNum)
	ciphertext = make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	signature = ntlmSign(cipher, signKey, seq, plaintext)
	return ciphertext, signature
}

// Unseal decrypts ciphertext using the RC4 sealing cipher and verifies it against
// signature (MS-NLMP §3.4.3, §3.4.4).
//
// cipher must be the caller's persistent sealing cipher for the sender, used in
// CONNECTION mode (see [Seal]). It returns an error if signature does not match.
func Unseal(cipher *rc4.Cipher, signKey []byte, signature, ciphertext []byte) ([]byte, error) {
	if len(signature) != 16 {
		return nil, errors.New("ntlmssp: signature must be 16 bytes")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)
	expected := ntlmSign(cipher, signKey, signature[12:16], plaintext)
	if !hmac.Equal(signature, expected) {
		return nil, errors.New("ntlmssp: signature mismatch")
	}
	return plaintext, nil
}

func newDerivedKey(sessionKey []byte, magicConstant string) []byte {
	keyIn := slices.Concat(sessionKey, []byte(magicConstant), []byte{0})
	sum := md5.Sum(keyIn)
	return sum[:]
}

func seqBytes(seqNum uint32) []byte {
	return []byte{byte(seqNum), byte(seqNum >> 8), byte(seqNum >> 16), byte(seqNum >> 24)}
}

// ntlmSign computes an NTLMSSP_MESSAGE_SIGNATURE (MS-NLMP §3.4.4).
// The sealing cipher state is advanced by this call (by 8 bytes for the encHmac XOR).
func ntlmSign(sealCipher *rc4.Cipher, signKey []byte, seq []byte, plaintext []byte) []byte {
	encHmac := make([]byte, 8)
	sealCipher.XORKeyStream(encHmac, hmacMd5(signKey, append(seq, plaintext...))[:8])
	// NTLMSSP_MESSAGE_SIGNATURE layout: version(4) | encHmac(8) | seq(4)
	return slices.Concat([]byte(versionMagic), encHmac, seq)
}
