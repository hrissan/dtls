// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package signature

import (
	"hash"

	"github.com/hrissan/dtls/ciphersuite"
)

// [rfc8446:4.4.3]
var coveredContentPrefix = []byte("                                                                " +
	"TLS 1.3, server CertificateVerify\x00")

// like hash.Sum, appends hash to data and returns it
func CalculateCoveredContentHash(hasher hash.Hash, certVerifyTranscriptHash []byte) ciphersuite.Hash {
	_, _ = hasher.Write(coveredContentPrefix)
	_, _ = hasher.Write(certVerifyTranscriptHash)

	var result ciphersuite.Hash
	result.SetSum(hasher)
	return result
}
