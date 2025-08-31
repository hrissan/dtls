// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package chat

import "fmt"

const PSKClientIdentity = "Client_identity"

func PSKAppendSecret(peerIdentity []byte, scratch []byte) []byte {
	if string(peerIdentity) == PSKClientIdentity {
		fmt.Printf("PSK known client identity: %q\n", peerIdentity)
		return append(scratch, 0x1a, 0x2b, 0x3c, 0x4d) // matches wolfssl examples to test interop
	}
	return nil
}
