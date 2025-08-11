package keys

import (
	"crypto/sha256"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/hkdf"
)

type Keys struct {
	ServerRandom [32]byte
	X25519Secret [32]byte

	ClientHandshakeTrafficSecret [32]byte
	ServerHandshakeTrafficSecret [32]byte

	MasterSecret [32]byte

	ClientWriteKey [16]byte
	ServerWriteKey [16]byte
	ClientWriteIV  [12]byte
	ServerWriteIV  [12]byte

	NextMessageSeqSend    uint32
	NextMessageSeqReceive uint32
}

func (keys *Keys) ComputeHandshakeKeys(sharedSecret []byte, trHash []byte) {
	hasher := sha256.New()
	emptyHash := sha256.Sum256(nil)

	salt := []byte{}
	psk := [32]byte{}
	earlySecret := hkdf.Extract(hasher, salt, psk[:])

	derivedSecret := deriveSecret(hasher, earlySecret, "derived", emptyHash[:])
	handshakeSecret := hkdf.Extract(hasher, derivedSecret, sharedSecret)
	copy(keys.ClientHandshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "c hs traffic", trHash[:]))
	copy(keys.ServerHandshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "s hs traffic", trHash[:]))
	log.Printf("client handshake keys: %x\n", keys.ClientHandshakeTrafficSecret)
	log.Printf("server handshake keys: %x\n", keys.ServerHandshakeTrafficSecret)

	derivedSecret = deriveSecret(hasher, handshakeSecret, "derived", emptyHash[:])
	zeros := [32]byte{}
	masterSecret := hkdf.Extract(hasher, derivedSecret, zeros[:])
	copy(keys.MasterSecret[:], masterSecret)
	csecret := keys.ClientHandshakeTrafficSecret[:]
	ssecret := keys.ServerHandshakeTrafficSecret[:]
	copy(keys.ClientWriteKey[:], hkdf.ExpandLabel(hasher, csecret, "key", []byte{}, len(keys.ClientWriteKey)))
	copy(keys.ServerWriteKey[:], hkdf.ExpandLabel(hasher, ssecret, "key", []byte{}, len(keys.ServerWriteKey)))
	copy(keys.ClientWriteIV[:], hkdf.ExpandLabel(hasher, csecret, "iv", []byte{}, len(keys.ClientWriteIV)))
	copy(keys.ServerWriteIV[:], hkdf.ExpandLabel(hasher, ssecret, "iv", []byte{}, len(keys.ServerWriteIV)))
}

func deriveSecret(hasher hash.Hash, secret []byte, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hasher, secret, label, sum, len(sum))
}
