// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"fmt"
	"unsafe" // must be the only "unsafe" we have.

	"github.com/hrissan/dtls/keys"
)

// TODO - move this file to tests too check we did not accidentally increased sizeof()

func PrintSizeofInfo() {
	fmt.Printf(
		`Sizeof(various objects):
hctx:        %d (+large buffers for message reassembly, released after successful handshake)
Connection:       %d (+960 bytes (+480 if using plaintext sequence numbers) in AES contexts)
Keys:             %d (part of Connection, contain pair of Directional Keys + Symmetric Keys for next receiving epoch)
Directional Keys: %d (Contain Symmetric Keys + Secrets for key update) 
Symmetric Keys:   %d (For TLS_AES_128_GCM_SHA256)
`,
		unsafe.Sizeof(handshakeContext{}),
		unsafe.Sizeof(ConnectionImpl{}),
		unsafe.Sizeof(keys.Keys{}),
		unsafe.Sizeof(keys.DirectionKeys{}),
		unsafe.Sizeof(keys.SymmetricKeys{}))
}
