// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package keys

import (
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/hkdf"
)

type DirectionKeys struct {
	ApplicationTrafficSecret [32]byte // we need to keep this for key update

	Symmetric ciphersuite.SymmetricKeys

	// total size ~100 plus 240 (no seq encryption) or 480 (seq encryption)
	// but crypto.Block in standard golang's crypto contains both encrypting and decrypting halves,
	// so without unsafe tricks our direction keys total size is ~100 plus 480 (no seq encryption) or 960 (seq encryption)
}

func (keys *DirectionKeys) ComputeHandshakeKeys(roleServer bool, handshakeSecret []byte, trHash []byte) (handshakeTrafficSecret [32]byte) {
	if keys.Symmetric.Epoch != 0 {
		panic("handshake keys state machine violation")
	}

	hasher := sha256.New()
	if roleServer {
		copy(handshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "s hs traffic", trHash[:]))
		fmt.Printf("server2 handshake traffic secret: %x\n", handshakeTrafficSecret)
	} else {
		copy(handshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "c hs traffic", trHash[:]))
		fmt.Printf("client2 handshake traffic secret: %x\n", handshakeTrafficSecret)
	}
	keys.Symmetric.ComputeKeys(handshakeTrafficSecret[:])

	keys.Symmetric.Epoch = 2
	return handshakeTrafficSecret
}

// TODO - remove allocations
func ComputeFinished(hasher hash.Hash, HandshakeTrafficSecret []byte, transcriptHash []byte) []byte {
	finishedKey := hkdf.ExpandLabel(hasher, HandshakeTrafficSecret, "finished", []byte{}, hasher.Size())
	return hkdf.HMAC(finishedKey, transcriptHash[:], hasher)
}

func (keys *DirectionKeys) ComputeApplicationTrafficSecret(roleServer bool, masterSecret []byte, trHash []byte) {
	hasher := sha256.New()
	if roleServer {
		copy(keys.ApplicationTrafficSecret[:], deriveSecret(hasher, masterSecret[:], "s ap traffic", trHash[:]))
		fmt.Printf("server2 application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	} else {
		copy(keys.ApplicationTrafficSecret[:], deriveSecret(hasher, masterSecret[:], "c ap traffic", trHash[:]))
		fmt.Printf("client2 application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	}
}

func (keys *DirectionKeys) ComputeNextApplicationTrafficSecret(direction string) {
	// [rfc8446:7.2]
	// The next-generation application_traffic_secret is computed as:
	//
	// application_traffic_secret_N+1 =
	//	HKDF-Expand-Label(application_traffic_secret_N,
	//		"traffic upd", "", Hash.length)
	hasher := sha256.New()
	copy(keys.ApplicationTrafficSecret[:], hkdf.ExpandLabel(hasher, keys.ApplicationTrafficSecret[:], "traffic upd", []byte{}, len(keys.ApplicationTrafficSecret)))
	fmt.Printf("next %s application traffic secret: %x\n", direction, keys.ApplicationTrafficSecret)
}
