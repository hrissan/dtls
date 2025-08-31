// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package ciphersuite

import (
	"encoding/binary"

	"github.com/hrissan/dtls/record"
)

type SymmetricKeys interface {
	RecordOverhead() (AEADSealSize int, MinCiphertextSize int)

	// error if called with too short ciphertext
	EncryptSeqMask(ciphertext []byte) ([2]byte, error)

	// [.................................................] <-- datagramLeft
	// [.hdr.]
	//        [....plaintext....]
	//                           [.AEAD seal.]
	//        [..........ciphertext..........]
	// Encrypts in place, with hdr as additional data and puts AEAD seal after plaintext.
	// len(datagramLeft) >= hdrSize + plaintextSize + AEADSealSize
	AEADEncrypt(seq uint64, datagramLeft []byte, hdrSize int, plaintextSize int)

	// Warning - decrypts in place, seqNumData and body can be garbage after unsuccessfull decryption
	// [.....................................]
	// [.....] <-- rec.Header
	//        [........rec.Ciphertext........]
	//                           [.AEAD seal.]
	//        [....plaintext....]
	// Deencrypts in place, with rec.Header as additional data
	// len(rec.Ciphertext) == plaintextSize + AEADSealSize
	AEADDecrypt(rec record.Encrypted, seq uint64) (plaintextSize int, err error)
}

// panic if len(iv) is < 8
func FillIVSequence(iv []byte, seq uint64) {
	maskBytes := iv[len(iv)-8:]
	mask := binary.BigEndian.Uint64(maskBytes)
	binary.BigEndian.PutUint64(maskBytes, seq^mask)
}
