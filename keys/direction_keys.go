// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package keys

import (
	"fmt"

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

func (keys *DirectionKeys) ComputeHandshakeKeys(suite ciphersuite.Suite, roleServer bool, handshakeSecret []byte, trHash []byte) (handshakeTrafficSecret [32]byte) {
	if keys.Symmetric.Epoch != 0 {
		panic("handshake keys state machine violation")
	}

	hmacHandshakeSecret := suite.NewHMAC(handshakeSecret)
	if roleServer {
		copy(handshakeTrafficSecret[:], deriveSecret(hmacHandshakeSecret, "s hs traffic", trHash[:]))
		fmt.Printf("server2 handshake traffic secret: %x\n", handshakeTrafficSecret)
	} else {
		copy(handshakeTrafficSecret[:], deriveSecret(hmacHandshakeSecret, "c hs traffic", trHash[:]))
		fmt.Printf("client2 handshake traffic secret: %x\n", handshakeTrafficSecret)
	}
	keys.Symmetric.ComputeKeys(suite, handshakeTrafficSecret[:])

	keys.Symmetric.Epoch = 2
	return handshakeTrafficSecret
}

// TODO - remove allocations
func ComputeFinished(suite ciphersuite.Suite, HandshakeTrafficSecret []byte, transcriptHash ciphersuite.Hash) ciphersuite.Hash {
	hmacHandshakeTrafficSecret := suite.NewHMAC(HandshakeTrafficSecret)
	finishedKey := hkdf.ExpandLabel(hmacHandshakeTrafficSecret, "finished", []byte{}, hmacHandshakeTrafficSecret.Size())
	var result ciphersuite.Hash
	hmacFinishedKey := suite.NewHMAC(finishedKey)
	hmacFinishedKey.Write(transcriptHash.GetValue())
	result.SetSum(hmacFinishedKey)
	return result
}

func (keys *DirectionKeys) ComputeApplicationTrafficSecret(suite ciphersuite.Suite, roleServer bool, masterSecret []byte, trHash []byte) {
	hmacMasterSecret := suite.NewHMAC(masterSecret)
	if roleServer {
		copy(keys.ApplicationTrafficSecret[:], deriveSecret(hmacMasterSecret, "s ap traffic", trHash[:]))
		fmt.Printf("server2 application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	} else {
		copy(keys.ApplicationTrafficSecret[:], deriveSecret(hmacMasterSecret, "c ap traffic", trHash[:]))
		fmt.Printf("client2 application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	}
}

func (keys *DirectionKeys) ComputeNextApplicationTrafficSecret(suite ciphersuite.Suite, direction string) {
	// [rfc8446:7.2]
	// The next-generation application_traffic_secret is computed as:
	//
	// application_traffic_secret_N+1 =
	//	HKDF-Expand-Label(application_traffic_secret_N,
	//		"traffic upd", "", Hash.length)
	hmacApplicationTrafficSecret := suite.NewHMAC(keys.ApplicationTrafficSecret[:])
	copy(keys.ApplicationTrafficSecret[:], hkdf.ExpandLabel(hmacApplicationTrafficSecret, "traffic upd", []byte{}, len(keys.ApplicationTrafficSecret)))
	fmt.Printf("next %s application traffic secret: %x\n", direction, keys.ApplicationTrafficSecret)
}
