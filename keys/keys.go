package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"hash"

	"github.com/hrissan/tinydtls/hkdf"
)

var ErrCipherTextTooShortForSNDecryption = errors.New("ciphertext too short for SN decryption")

type Keys struct {
	// fields sorted to minimize padding
	Send    DirectionKeys
	Receive DirectionKeys

	// for ServerHello retransmit and replay protection
	SendNextSegmentSequenceEpoch0 uint64 // TODO - reduce to 16 bit?
	SendNextSegmentSequence       uint64

	// No replay protection for Epoch 0
	ReceiveNextSegmentSequence uint64

	NewReceiveKeys SymmetricKeys // always correspond to Receive.Symmetric.Epoch + 1

	FailedDeprotectionCounter               uint64
	NewReceiveKeysFailedDeprotectionCounter uint64

	// this counter does not reset with a new epoch
	NextMessageSeqSend    uint16
	NextMessageSeqReceive uint16

	DoNotEncryptSequenceNumbers bool // enabled extensions and saves us 50% memory on crypto contexts
	ExpectEpochUpdate           bool // waiting for the next epoch during handshake or key update
	NewReceiveKeysSet           bool
}

func NewAesCipher(key []byte) cipher.Block {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic("aes.NewCipher fails " + err.Error())
	}
	return c
}

func NewGCMCipher(block cipher.Block) cipher.AEAD {
	c, err := cipher.NewGCM(block)
	if err != nil {
		panic("cipher.NewGCM fails " + err.Error())
	}
	return c
}

func (keys *Keys) ComputeHandshakeKeys(serverRole bool, sharedSecret []byte, trHash []byte) (
	masterSecret [32]byte, handshakeTrafficSecretSend [32]byte, handshakeTrafficSecretReceive [32]byte) {
	hasher := sha256.New()
	emptyHash := sha256.Sum256(nil)

	salt := []byte{}
	psk := [32]byte{}
	earlySecret := hkdf.Extract(hasher, salt, psk[:])

	derivedSecret := deriveSecret(hasher, earlySecret, "derived", emptyHash[:])
	handshakeSecret := hkdf.Extract(hasher, derivedSecret, sharedSecret)

	handshakeTrafficSecretSend = keys.Send.ComputeHandshakeKeys(serverRole, handshakeSecret, trHash)
	keys.SendNextSegmentSequence = 0

	handshakeTrafficSecretReceive = keys.Receive.ComputeHandshakeKeys(!serverRole, handshakeSecret, trHash)
	keys.ReceiveNextSegmentSequence = 0
	keys.ExpectEpochUpdate = true

	derivedSecret = deriveSecret(hasher, handshakeSecret, "derived", emptyHash[:])
	zeros := [32]byte{}
	masterSecretSlice := hkdf.Extract(hasher, derivedSecret, zeros[:])
	copy(masterSecret[:], masterSecretSlice)
	return
}

func (keys *Keys) ComputeApplicationTrafficSecret(serverRole bool, masterSecret []byte, trHash []byte) {
	keys.Send.ComputeApplicationTrafficSecret(serverRole, masterSecret, trHash)
	keys.Receive.ComputeApplicationTrafficSecret(!serverRole, masterSecret, trHash)
}

func deriveSecret(hasher hash.Hash, secret []byte, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hasher, secret, label, sum, len(sum))
}
