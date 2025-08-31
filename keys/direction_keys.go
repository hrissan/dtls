// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package keys

import (
	"fmt"
	"hash"

	"github.com/hrissan/dtls/ciphersuite"
)

type DirectionKeys struct {
	Symmetric                ciphersuite.SymmetricKeys
	ApplicationTrafficSecret ciphersuite.Hash // we need to keep this for key update
	Epoch                    uint16
}

func (keys *DirectionKeys) ComputeHandshakeKeys(suite ciphersuite.Suite, roleServer bool, hmacHandshakeSecret hash.Hash, trHash ciphersuite.Hash) (handshakeTrafficSecret ciphersuite.Hash) {
	if roleServer {
		handshakeTrafficSecret = deriveSecret(hmacHandshakeSecret, "s hs traffic", trHash)
		fmt.Printf("server2 handshake traffic secret: %x\n", handshakeTrafficSecret)
	} else {
		handshakeTrafficSecret = deriveSecret(hmacHandshakeSecret, "c hs traffic", trHash)
		fmt.Printf("client2 handshake traffic secret: %x\n", handshakeTrafficSecret)
	}
	suite.ResetSymmetricKeys(&keys.Symmetric, handshakeTrafficSecret)
	return handshakeTrafficSecret
}

// TODO - remove allocations
func ComputeFinished(suite ciphersuite.Suite, HandshakeTrafficSecret ciphersuite.Hash, transcriptHash ciphersuite.Hash) ciphersuite.Hash {
	hmacHandshakeTrafficSecret := suite.NewHMAC(HandshakeTrafficSecret.GetValue())
	var finishedKey ciphersuite.Hash
	finishedKey.SetZero(hmacHandshakeTrafficSecret.Size())
	ciphersuite.HKDFExpandLabel(finishedKey.GetValue(), hmacHandshakeTrafficSecret, "finished", nil)
	var result ciphersuite.Hash
	hmacFinishedKey := suite.NewHMAC(finishedKey.GetValue())
	hmacFinishedKey.Write(transcriptHash.GetValue())
	result.SetSum(hmacFinishedKey)
	return result
}

func (keys *DirectionKeys) ComputeApplicationTrafficSecret(suite ciphersuite.Suite, roleServer bool, masterSecret ciphersuite.Hash, trHash ciphersuite.Hash) {
	hmacMasterSecret := suite.NewHMAC(masterSecret.GetValue())
	if roleServer {
		keys.ApplicationTrafficSecret = deriveSecret(hmacMasterSecret, "s ap traffic", trHash)
		fmt.Printf("server2 application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	} else {
		keys.ApplicationTrafficSecret = deriveSecret(hmacMasterSecret, "c ap traffic", trHash)
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
	hmacApplicationTrafficSecret := suite.NewHMAC(keys.ApplicationTrafficSecret.GetValue())
	keys.ApplicationTrafficSecret.SetZero(hmacApplicationTrafficSecret.Size())
	ciphersuite.HKDFExpandLabel(keys.ApplicationTrafficSecret.GetValue(), hmacApplicationTrafficSecret, "traffic upd", nil)
	fmt.Printf("next %s application traffic secret: %x\n", direction, keys.ApplicationTrafficSecret)
}
