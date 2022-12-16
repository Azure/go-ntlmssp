package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type avID uint16

type AvPairs map[avID][]byte

func NewAvPairs() AvPairs {
	return make(AvPairs)
}

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

func (pairs AvPairs) unmarshal(data []byte) error {

	r := bytes.NewReader(data)
	for {
		var id avID
		var l uint16
		err := binary.Read(r, binary.LittleEndian, &id)
		if err != nil {
			return err
		}
		if id == avIDMsvAvEOL {
			break
		}

		err = binary.Read(r, binary.LittleEndian, &l)
		if err != nil {
			return err
		}
		value := make([]byte, l)
		n, err := r.Read(value)
		if err != nil {
			return err
		}
		if n != int(l) {
			return fmt.Errorf("Expected to read %d bytes, got only %d", l, n)
		}
		(pairs)[id] = value
	}
	return nil
}

func (pairs AvPairs) marshal() ([]byte, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, 2))

	for id := avIDMsvAvNbComputerName; id <= avIDMsvChannelBindings; id++ {
		value := (pairs)[id]
		if value != nil {
			if err := binary.Write(buffer, binary.LittleEndian, id); err != nil {
				return nil, err
			}
			if err := binary.Write(buffer, binary.LittleEndian, uint16(len(value))); err != nil {
				return nil, err
			}
			_, err := buffer.Write(value)
			if err != nil {
				return nil, err
			}
		}
	}
	if err := binary.Write(buffer, binary.LittleEndian, avIDMsvAvEOL); err != nil {
		return nil, err
	}
	_, err := buffer.Write([]byte{0, 0})
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

type AvFlags uint32

func (f *AvFlags) Set(flag AvFlags) {
	*f = *f | flag
}

const (
	AvFlagAuthenticationConstrained AvFlags = 0x00000001 // Indicates to the client that the account authentication is constrained.
	AvFlagMICPresent                AvFlags = 0x00000002 // Indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.<14>
	AvFlagUntrustedSPN              AvFlags = 0x00000004 // Indicates that the client is providing a target SPN generated from an untrusted source.<15>
)
