package handler

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzMQTTReadVarint exercises the MQTT remaining-length varint parser
// (per spec, 1-4 bytes, big-endian-ish). The spec caps at 4 bytes; we
// must never spin forever or panic on weird input.
func FuzzMQTTReadVarint(f *testing.F) {
	f.Add([]byte{0x00})                   // length 0
	f.Add([]byte{0x7F})                   // length 127, single byte
	f.Add([]byte{0x80, 0x01})             // length 128
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0x7F}) // max valid (268435455)
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // illegal 5-byte
	f.Add([]byte{})                       // empty
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("readVarint panicked: %v", r)
			}
		}()
		br := bufio.NewReader(bytes.NewReader(data))
		_, _ = readVarint(br)
	})
}

// FuzzMQTTReadString exercises the length-prefixed-string reader.
func FuzzMQTTReadString(f *testing.F) {
	f.Add([]byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}, 0)
	f.Add([]byte{0xFF, 0xFF}, 0)
	f.Add([]byte{}, 0)
	f.Add([]byte{0x00, 0x00}, 0)
	f.Fuzz(func(t *testing.T, data []byte, idx int) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("readMQTTString panicked: %v", r)
			}
		}()
		_, _, _ = readMQTTString(data, idx)
	})
}
