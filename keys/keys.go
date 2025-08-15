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
	MasterSecret [32]byte

	Send    DirectionKeys
	Receive DirectionKeys

	FailedDeprotectionCounter uint64

	// this counter does not reset with a new epoch
	NextMessageSeqSend    uint16
	NextMessageSeqReceive uint16

	DoNotEncryptSequenceNumbers bool // enabled extensions and saves us 50% memory on crypto contexts
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

func (keys *Keys) ComputeHandshakeKeys(serverRole bool, sharedSecret []byte, trHash []byte) {
	hasher := sha256.New()
	emptyHash := sha256.Sum256(nil)

	salt := []byte{}
	psk := [32]byte{}
	earlySecret := hkdf.Extract(hasher, salt, psk[:])

	derivedSecret := deriveSecret(hasher, earlySecret, "derived", emptyHash[:])
	handshakeSecret := hkdf.Extract(hasher, derivedSecret, sharedSecret)

	keys.Send.ComputeHandshakeKeys(serverRole, handshakeSecret, trHash)
	keys.Receive.ComputeHandshakeKeys(!serverRole, handshakeSecret, trHash)

	derivedSecret = deriveSecret(hasher, handshakeSecret, "derived", emptyHash[:])
	zeros := [32]byte{}
	masterSecret := hkdf.Extract(hasher, derivedSecret, zeros[:])
	copy(keys.MasterSecret[:], masterSecret)
}

func (keys *Keys) ComputeApplicationTrafficSecret(serverRole bool, trHash []byte) {
	keys.Send.ComputeApplicationTrafficSecret(serverRole, keys.MasterSecret[:], trHash)
	keys.Receive.ComputeApplicationTrafficSecret(!serverRole, keys.MasterSecret[:], trHash)
	//hasher := sha256.New()
	//copy(keys.ClientApplicationTrafficSecret[:], deriveSecret(hasher, keys.MasterSecret[:], "c ap traffic", trHash[:]))
	//copy(keys.ServerApplicationTrafficSecret[:], deriveSecret(hasher, keys.MasterSecret[:], "s ap traffic", trHash[:]))
	//log.Printf("client application traffic secret: %x\n", keys.ClientApplicationTrafficSecret)
	//log.Printf("server application traffic secret: %x\n", keys.ServerApplicationTrafficSecret)
	// [rfc8446:7.2]
	//The next-generation application_traffic_secret is computed as:
	//
	//application_traffic_secret_N+1 =
	//	HKDF-Expand-Label(application_traffic_secret_N,
	//		"traffic upd", "", Hash.length)
}

func (keys *Keys) ComputeServerApplicationKeys() {
	//hasher := sha256.New()
	//ssecret := keys.ServerApplicationTrafficSecret[:]
	//copy(keys.ServerWriteKey[:], hkdf.ExpandLabel(hasher, ssecret, "key", []byte{}, len(keys.ServerWriteKey)))
	//copy(keys.ServerWriteIV[:], hkdf.ExpandLabel(hasher, ssecret, "iv", []byte{}, len(keys.ServerWriteIV)))
	//TODO - update epoch/seq
	//keys.Epoch = 3
	//keys.NextSegmentSequenceReceive = 0
}

func (keys *Keys) ComputeClientApplicationKeys() {
	//hasher := sha256.New()
	//csecret := keys.ClientApplicationTrafficSecret[:]
	//copy(keys.ClientWriteKey[:], hkdf.ExpandLabel(hasher, csecret, "key", []byte{}, len(keys.ClientWriteKey)))
	//copy(keys.ClientWriteIV[:], hkdf.ExpandLabel(hasher, csecret, "iv", []byte{}, len(keys.ClientWriteIV)))
	//TODO - update epoch/seq
	//keys.Epoch = 3
	//keys.NextSegmentSequenceReceive = 0
}

func deriveSecret(hasher hash.Hash, secret []byte, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hasher, secret, label, sum, len(sum))
}
