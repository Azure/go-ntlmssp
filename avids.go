// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"encoding/binary"
	"errors"
)

type avID uint16

const (
	avIDMsvAvEOL avID = iota
	avIDMsvAvNbComputerName
	avIDMsvAvNbDomainName
	avIDMsvAvDNSComputerName
	avIDMsvAvDNSDomainName
	avIDMsvAvDNSTreeName
	avIDMsvAvFlags
	avIDMsvAvTimestamp
	avIDMsvAvSingleHost
	avIDMsvAvTargetName
	avIDMsvChannelBindings
)

// avFlagMICProvided is the MsvAvFlags bit indicating that the client is
// providing a MIC in the AUTHENTICATE message (MS-NLMP 2.2.2.1).
const avFlagMICProvided = 0x00000002

// withMICFlag returns a copy of the targetInfo AV_PAIR list with the
// MIC-provided bit set in MsvAvFlags, adding that pair before MsvAvEOL if it
// is absent (MS-NLMP 3.1.5.1.2).
func withMICFlag(targetInfo []byte) ([]byte, error) {
	out := make([]byte, 0, len(targetInfo)+8)
	found := false
	for len(targetInfo) >= 4 {
		id := avID(binary.LittleEndian.Uint16(targetInfo))
		l := int(binary.LittleEndian.Uint16(targetInfo[2:]))
		if id == avIDMsvAvEOL {
			break
		}
		if len(targetInfo) < 4+l {
			return nil, errors.New("AV_PAIR extends beyond target info")
		}
		start := len(out)
		out = append(out, targetInfo[:4+l]...)
		targetInfo = targetInfo[4+l:]
		if id == avIDMsvAvFlags && l == 4 {
			v := out[start+4:]
			binary.LittleEndian.PutUint32(v, binary.LittleEndian.Uint32(v)|avFlagMICProvided)
			found = true
		}
	}
	if !found {
		out = binary.LittleEndian.AppendUint16(out, uint16(avIDMsvAvFlags))
		out = binary.LittleEndian.AppendUint16(out, 4)
		out = binary.LittleEndian.AppendUint32(out, avFlagMICProvided)
	}
	return append(out, 0, 0, 0, 0), nil // MsvAvEOL
}
