package ntlmssp

import (
	"bytes"
	"reflect"
	"testing"
)

func TestMarshalAVPairs(t *testing.T) {
	tests := []struct {
		name     string
		input    AvPairs
		expected []byte
	}{
		{"empty", AvPairs{}, []byte{0x00, 0x00, 0x00, 0x00}}, // avIDMsvAvEOL, len(0)
		{"with 2 pairs",
			AvPairs{
				avIDMsvAvTargetName:   []byte{0, 0},
				avIDMsvAvNbDomainName: []byte{1, 1, 1, 1},
			},
			[]byte{
				0x02, 0x00, 0x04, 0x00, 0x01, 0x01, 0x01, 0x01, // avIDMsvAvNbDomainName, len(4), 1, 1, 1, 1
				0x09, 0x00, 0x02, 0x00, 0x00, 0x00, // avIDMsvAvTargetName, len(2), 0, 0
				0x00, 0x00, 0x00, 0x00}, // avIDMsvAvEOL, len(0)
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.input.marshal()
			if err != nil {
				t.Errorf("Expected no errors, but got %v", err)
			}
			if data == nil {
				t.Fatalf("Expected written data to not be null")
			}
			if len(tc.expected) != len(data) {
				t.Fatalf("Expected %d bytes, but got %d", len(tc.expected), len(data))
			}

			if !bytes.Equal(tc.expected, data) {
				t.Errorf("Expected %v, but got %v", tc.expected, data)
			}
		})
	}
}

func TestUnmarshalAVPairsWithTwoElements(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected AvPairs
	}{
		{"empty",
			[]byte{0x00, 0x00},
			NewAvPairs()}, // avIDMsvAvEOL1
		{"with 2 pairs",
			[]byte{
				0x02, 0x00, 0x04, 0x00, 0x01, 0x01, 0x01, 0x01, // avIDMsvAvNbDomainName, len(4), 1, 1, 1, 1
				0x09, 0x00, 0x02, 0x00, 0x00, 0x00, // avIDMsvAvTargetName, len(2), 0, 0
				0x00, 0x00}, // avIDMsvAvEOL
			func() AvPairs {
				pairs := NewAvPairs()
				pairs[avIDMsvAvTargetName] = []byte{0, 0}
				pairs[avIDMsvAvNbDomainName] = []byte{1, 1, 1, 1}
				return pairs
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			marshalled := tc.input

			result := NewAvPairs()
			err := result.unmarshal(marshalled)

			if err != nil {
				t.Fatalf("Expected read data to not be null")
			}
			if len(tc.expected) != len(result) {
				t.Fatalf("Expected %d entries, but got %d", len(tc.expected), len(result))
			}
			if !reflect.DeepEqual(tc.expected, result) {
				t.Fatalf("Expected %v, but got %v", tc.expected, result)
			}
		})
	}
}
