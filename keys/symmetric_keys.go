package keys

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"

	"github.com/hrissan/tinydtls/hkdf"
)

type SymmetricKeys struct {
	SN      cipher.Block // 16 interface + 240 aes half + (240 aes half we do not need). Can be removed with unencrypted sequence numbers extension
	Write   cipher.AEAD  // 16 interface + 16 interface inside + 16 (counters) + 240 aes half + (240 aes half we do not need)
	WriteIV [12]byte

	Epoch uint16
}

func (keys *SymmetricKeys) ComputeKeys(secret []byte) {
	const keySize = 16 // TODO - should depend on cipher suite
	hasher := sha256.New()
	writeKey := hkdf.ExpandLabel(hasher, secret, "key", []byte{}, keySize)
	copy(keys.WriteIV[:], hkdf.ExpandLabel(hasher, secret, "iv", []byte{}, len(keys.WriteIV)))
	snKey := hkdf.ExpandLabel(hasher, secret, "sn", []byte{}, keySize)

	keys.Write = NewGCMCipher(NewAesCipher(writeKey))
	keys.SN = NewAesCipher(snKey)
}

func (keys *SymmetricKeys) EncryptSequenceNumbers(seqNum []byte, cipherText []byte) error {
	var mask [32]byte // Some space good for many ciphers, TODO - check constant mush earlier
	if len(cipherText) < keys.SN.BlockSize() {
		// TODO - generate alert
		return ErrCipherTextTooShortForSNDecryption
	}
	keys.SN.Encrypt(mask[:], cipherText)
	if len(seqNum) == 1 {
		seqNum[0] ^= mask[0]
		return nil
	}
	if len(seqNum) == 2 {
		seqNum[0] ^= mask[0]
		seqNum[1] ^= mask[1]
		return nil
	}
	panic("seqNum must have 1 or 2 bytes")
}

// panic if len(iv) is < 8
func FillIVSequence(iv []byte, seq uint64) {
	maskBytes := iv[len(iv)-8:]
	mask := binary.BigEndian.Uint64(maskBytes)
	binary.BigEndian.PutUint64(maskBytes, seq^mask)
}
