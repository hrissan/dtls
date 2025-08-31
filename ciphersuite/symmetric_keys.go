// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"encoding/binary"

	"github.com/hrissan/dtls/record"
)

type SymmetricKeys interface {
	EncryptSeqMask(cipherText []byte) ([2]byte, error)

	RecordOverhead() (AEADSealSize int, MinCiphertextSize int)

	AEADEncrypt(seq uint64, datagramLeft []byte, hdrSize int, insideSize int)

	// Warning - decrypts in place, seqNumData and body can be garbage after unsuccessfull decryption
	AEADDecrypt(hdr record.Ciphertext, seq uint64) (decrypted []byte, err error)
}

// panic if len(iv) is < 8
func FillIVSequence(iv []byte, seq uint64) {
	maskBytes := iv[len(iv)-8:]
	mask := binary.BigEndian.Uint64(maskBytes)
	binary.BigEndian.PutUint64(maskBytes, seq^mask)
}
