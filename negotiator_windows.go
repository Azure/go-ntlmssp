// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	secur32 = syscall.NewLazyDLL("secur32.dll")

	procAcquireCredentials        = secur32.NewProc("AcquireCredentialsHandleW")
	procInitializeSecurityContext = secur32.NewProc("InitializeSecurityContextW")
	procFreeContextBuffer         = secur32.NewProc("FreeContextBuffer")
	procFreeCredentialsHandle     = secur32.NewProc("FreeCredentialsHandle")
)

type credHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

type ctxtHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

type secBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   uintptr
}

type secBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  uintptr
}

var packageName, _ = syscall.UTF16PtrFromString("NTLM")

type authContext struct {
	cred credHandle
	ctx  ctxtHandle

	user         string
	password     string
	domainNeeded bool
}

func newNegotiatedMessageSys() (authContext, []byte, error) {
	var cred credHandle
	var expiry syscall.Filetime

	// Acquire outbound credentials for NTLM
	if status, _, err := procAcquireCredentials.Call(
		0, // pszPrincipal - 0 means use current user
		uintptr(unsafe.Pointer(packageName)),
		2,          // SECPKG_CRED_OUTBOUND
		0, 0, 0, 0, // Not used
		uintptr(unsafe.Pointer(&cred)),
		uintptr(unsafe.Pointer(&expiry)),
	); status != 0 {
		return authContext{}, nil, err
	}
	var outBuf secBuffer
	outBuf.BufferType = 2 // SECBUFFER_TOKEN
	outDesc := secBufferDesc{
		ulVersion: 0,
		cBuffers:  1,
		pBuffers:  uintptr(unsafe.Pointer(&outBuf)),
	}
	// Initialize security context with challenge
	var outAttrs uint32
	var ctx ctxtHandle
	status, _, err := procInitializeSecurityContext.Call(
		uintptr(unsafe.Pointer(&cred)),
		0,          // No existing context
		0,          // pszTargetName - not used
		0x00000800, // ISC_REQ_ALLOCATE_MEMORY
		0,          // Reserved1
		0x10,       // SECURITY_NATIVE_DREP
		0,          // No input buffer
		0,          // Reserved2
		uintptr(unsafe.Pointer(&ctx)),
		uintptr(unsafe.Pointer(&outDesc)),
		uintptr(unsafe.Pointer(&outAttrs)),
		0, // ptsExpiry - not used
	)
	if status != 0 && status != 0x90312 { // SEC_I_CONTINUE_NEEDED
		return authContext{}, nil, fmt.Errorf("InitializeSecurityContext failed: 0x%x: %w", status, err)
	}
	defer procFreeContextBuffer.Call(outBuf.pvBuffer)
	// Copy output buffer to byte slice
	out := make([]byte, outBuf.cbBuffer)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(outBuf.pvBuffer)), outBuf.cbBuffer))
	return authContext{cred: cred, ctx: ctx}, out, nil
}

func processChallengeSys(ctx authContext, challenge []byte) ([]byte, error) {
	defer procFreeCredentialsHandle.Call(uintptr(unsafe.Pointer(&ctx.cred)))

	// Prepare output buffer for challenge

	inBuf := secBuffer{
		cbBuffer:   uint32(len(challenge)),
		BufferType: 2, // SECBUFFER_TOKEN
		pvBuffer:   uintptr(unsafe.Pointer(&challenge[0])),
	}
	inDesc := secBufferDesc{
		ulVersion: 0,
		cBuffers:  1,
		pBuffers:  uintptr(unsafe.Pointer(&inBuf)),
	}

	// Prepare output buffer
	var outBuf secBuffer
	outBuf.BufferType = 2 // SECBUFFER_TOKEN
	outDesc := secBufferDesc{
		ulVersion: 0,
		cBuffers:  1,
		pBuffers:  uintptr(unsafe.Pointer(&outBuf)),
	}
	// Initialize security context with challenge
	var outAttrs uint32
	status, _, err := procInitializeSecurityContext.Call(
		uintptr(unsafe.Pointer(&ctx.cred)),
		uintptr(unsafe.Pointer(&ctx.ctx)),
		0,          // pszTargetName - not used
		0x00000800, // ISC_REQ_ALLOCATE_MEMORY
		0,          // Reserved1
		0x10,       // SECURITY_NATIVE_DREP
		uintptr(unsafe.Pointer(&inDesc)),
		0, // Reserved2
		0, // Context handle not needed
		uintptr(unsafe.Pointer(&outDesc)),
		uintptr(unsafe.Pointer(&outAttrs)),
		0, // ptsExpiry - not used
	)
	if status != 0 && status != 0x90312 { // SEC_I_CONTINUE_NEEDED
		return nil, fmt.Errorf("InitializeSecurityContext failed: 0x%x: %w", status, err)
	}
	defer procFreeContextBuffer.Call(outBuf.pvBuffer)
	// Copy output buffer to byte slice
	out := make([]byte, outBuf.cbBuffer)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(outBuf.pvBuffer)), outBuf.cbBuffer))
	return out, nil
}
