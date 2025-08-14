package signature

import (
	"hash"

	"github.com/hrissan/tinydtls/constants"
)

// [rfc8446:4.4.3]
const CoveredContentPrefix = "                                                                " +
	"TLS 1.3, server CertificateVerify"

// like hash.Sum, appends hash to data and returns it
func CalculateCoveredContentHash(hasher hash.Hash, certVerifyTranscriptHash []byte, data []byte) []byte {
	var storage [len(CoveredContentPrefix) + 1 + constants.MaxHashLength]byte

	sigMessage := append(storage[:0], CoveredContentPrefix...)
	sigMessage = append(sigMessage, 0)
	sigMessage = append(sigMessage, certVerifyTranscriptHash...)

	_, _ = hasher.Write(sigMessage)
	return hasher.Sum(data)
}
