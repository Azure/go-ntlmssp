// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const (
	CLIENT_TO_SERVER_SIGNING = "session key to client-to-server signing key magic constant"
	CLIENT_TO_SERVER_SEALING = "session key to client-to-server sealing key magic constant"
	SERVER_TO_CLIENT_SIGNING = "session key to server-to-client signing key magic constant"
	SERVER_TO_CLIENT_SEALING = "session key to server-to-client sealing key magic constant"
	VERSION_MAGIC            = "\x01\x00\x00\x00"
)

func SealRequest(req *http.Request, body io.ReadCloser, sealCipher *rc4.Cipher, signKey []byte, seqNum uint32) error {
	// Read the plaintext body once — used for both HMAC and encryption below.
	plaintext, readErr := io.ReadAll(body)
	if readErr != nil {
		return nil
	}

	seq := []byte{byte(seqNum), byte(seqNum >> 8), byte(seqNum >> 16), byte(seqNum >> 24)}

	// Encrypt body with persistent RC4 cipher (MS-NLMP §3.4 CONNECTION mode).
	encBody := make([]byte, len(plaintext))
	sealCipher.XORKeyStream(encBody, plaintext)

	// sign the message
	sig := sign(sealCipher, signKey, seq, plaintext)

	// Binary payload per MS-WSMV §3.1.4.2:
	payload := slices.Concat([]byte{16, 0, 0, 0}, sig, encBody)

	// Multipart/encrypted body (MS-WSMV §3.1.4.2)
	var multipartBody bytes.Buffer
	multipartBody.WriteString("--Encrypted Boundary\r\n")
	multipartBody.WriteString("Content-Type: application/HTTP-SPNEGO-session-encrypted\r\n")
	multipartBody.WriteString("OriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + strconv.Itoa(len(plaintext)) + "\r\n")
	multipartBody.WriteString("--Encrypted Boundary\r\n")
	multipartBody.WriteString("Content-Type: application/octet-stream\r\n")
	multipartBody.Write(payload)
	multipartBody.WriteString("--Encrypted Boundary--\r\n")

	req.Body = io.NopCloser(&multipartBody)
	req.ContentLength = int64(multipartBody.Len())
	req.Header.Set("Content-Type", `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`)

	return nil
}

func UnsealResponse(resp *http.Response, sealCipher *rc4.Cipher, signKey []byte) error {
	if !strings.Contains(resp.Header.Get("Content-Type"), "multipart/encrypted") {
		// Not an encrypted response; leave it untouched.
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var emessage []byte
	for boundary := range bytes.SplitSeq(body, []byte("--Encrypted Boundary")) {
		if header, ok := bytes.CutPrefix(boundary, []byte("\r\nContent-Type: application/HTTP-SPNEGO-session-encrypted\r\nOriginalContent: ")); ok {
			header = bytes.TrimSuffix(header, []byte("\r\n"))
			for part := range bytes.SplitSeq(header, []byte(";")) {
				if after, ok := bytes.CutPrefix(part, []byte("Length=")); ok {
					length, err := strconv.ParseInt(string(after), 10, 64)
					if err != nil {
						return errors.New("invalid length in encrypted message header")
					}
					resp.ContentLength = int64(length)
					resp.Header.Set("Content-Length", string(after))
				} else if contentType, ok := bytes.CutPrefix(part, []byte("type=")); ok {
					resp.Header.Set("Content-Type", string(contentType))
				}
			}
		} else if data, ok := bytes.CutPrefix(boundary, []byte("\r\nContent-Type: application/octet-stream\r\n")); ok {
			emessage = data
		}
	}

	if len(emessage) < 20 {
		return errors.New("encrypted part too short to contain signature")
	}

	signature := emessage[4:20]
	ciphertext := emessage[20:]

	// Decrypt with persistent server RC4 cipher (continues where the last message left off).
	plaintext := make([]byte, len(ciphertext))
	sealCipher.XORKeyStream(plaintext, ciphertext)

	expectedSig := sign(sealCipher, signKey, signature[12:16], plaintext)
	if !bytes.Equal(signature, expectedSig) {
		return errors.New("invalid signature in sealed response")
	}

	resp.Body = io.NopCloser(bytes.NewReader(plaintext))
	return nil
}

func NewClientSignKey(sessionKey []byte) []byte {
	return newSessionKey(sessionKey, CLIENT_TO_SERVER_SIGNING)
}

func NewClientSealKey(sessionKey []byte) []byte {
	return newSessionKey(sessionKey, CLIENT_TO_SERVER_SEALING)
}

func NewServerSignKey(sessionKey []byte) []byte {
	return newSessionKey(sessionKey, SERVER_TO_CLIENT_SIGNING)
}

func NewServerSealKey(sessionKey []byte) []byte {
	return newSessionKey(sessionKey, SERVER_TO_CLIENT_SEALING)
}

func newSessionKey(sessionKey []byte, magicConstant string) []byte {
	keyIn := slices.Concat(sessionKey, []byte(magicConstant), []byte{0})
	keyArr := md5.Sum(keyIn)
	return keyArr[:]
}

// resetSession clears all session-key material so the next request triggers a fresh
// NTLM handshake. Cached credentials are intentionally left intact for re-auth.
func (l *Negotiator) resetSession() {
	l.ExportedSessionKey = nil
	l.clientSealCipher = nil
	l.clientSignKey = nil
	l.serverSealCipher = nil
	l.serverSignKey = nil
	l.clientSeqNum = 0
}

func sign(sealCipher *rc4.Cipher, signKey []byte, seq []byte, plaintext []byte) []byte {
	encHmac := make([]byte, 8)
	sealCipher.XORKeyStream(encHmac, hmacMd5(signKey, append(seq, plaintext...))[:8])
	// NTLMSSP_MESSAGE_SIGNATURE (16 bytes): version(4) | encHmac(8) | seq(4)
	return slices.Concat([]byte(VERSION_MAGIC), encHmac, seq)
}
