// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func TestNewChacha20Poly1305(t *testing.T) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	nonce := []byte{0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00}
	counter := uint32(1)
	ci, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		t.Error(err)
	}
	var result [64]byte
	ci.SetCounter(counter)
	ci.XORKeyStream(result[:], result[:])
	resultHex := "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
	if hex.EncodeToString(result[:]) != resultHex {
		t.Errorf("chacha20 wrong result")
	}
}
