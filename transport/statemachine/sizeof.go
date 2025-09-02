// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"fmt"
	"unsafe" // must be the only "unsafe" we have.

	"github.com/hrissan/dtls/ciphersuite"
)

// crypto/internal/fips140/aes/aes.go
type aesBlock struct {
	rounds int
	// Round keys, where only the first (rounds + 1) * (128 / 32) words are used.
	enc [60]uint32
	dec [60]uint32
}

// crypto/internal/fips140/aes/gcm/gcm_asm.go
type gcmPlatformData struct {
	productTable [256]byte
}

// crypto/internal/fips140/aes/gcm/gcm.go
type gcm struct {
	cipher    aesBlock
	nonceSize int
	tagSize   int
	gcmPlatformData
}

// golang.org/x/crypto/chacha20poly1305/chacha20poly1305.go
const chacha20poly1305KeySize = 32

type chacha20poly1305 struct {
	key [chacha20poly1305KeySize]byte
}

// TODO - move this file to tests too check we did not accidentally increased sizeof()

func PrintSizeofInfo() {
	keys_TLS_AES_128_GCM_SHA256 := unsafe.Sizeof(ciphersuite.SymmetricKeysAES{}) + unsafe.Sizeof(gcm{}) + unsafe.Sizeof(aesBlock{})
	keys_TLS_CHACHA20_POLY1305_SHA256 := unsafe.Sizeof(ciphersuite.SymmetricKeysChaCha20Poly1305{}) + unsafe.Sizeof(chacha20poly1305{})
	fmt.Printf(
		`Sizeof(various objects):
hctx:              %d (during handshake only, +large buffers for message reassembly)
Connection struct: %d (secrets + bookkeeping data, we add 3x size of keys, depending on ciphersuite)
----
Keys TLS_AES_128_GCM_SHA256:
Keys struct:       %d
GCM:               %d (contains 1 AES inside, half of which is wasted)
AES:               %d (half of which is wasted)
           Total:  %d (%d if waste is removed)
----
Keys TLS_CHACHA20_POLY1305_SHA256:
Keys struct:       %d
CHACHA20_POLY1305: %d
           Total:  %d
`,
		unsafe.Sizeof(handshakeContext{}),
		unsafe.Sizeof(Connection{}),
		unsafe.Sizeof(ciphersuite.SymmetricKeysAES{}),
		unsafe.Sizeof(gcm{}),
		unsafe.Sizeof(aesBlock{}),
		unsafe.Sizeof(Connection{})+3*keys_TLS_AES_128_GCM_SHA256,
		unsafe.Sizeof(Connection{})+3*(keys_TLS_AES_128_GCM_SHA256-240),
		unsafe.Sizeof(ciphersuite.SymmetricKeysChaCha20Poly1305{}),
		unsafe.Sizeof(chacha20poly1305{}),
		unsafe.Sizeof(Connection{})+3*keys_TLS_CHACHA20_POLY1305_SHA256)
}
