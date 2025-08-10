package transport

import (
	"crypto/sha256"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/hkdf"
)

func computeHandshakeKeys(sharedSecret []byte, trHash []byte, hctx *HandshakeContext) {
	hasher := sha256.New()
	emptyHash := sha256.Sum256(nil)

	salt := []byte{}
	psk := [32]byte{}
	earlySecret := hkdf.Extract(hasher, salt, psk[:])

	derivedSecret := deriveSecret(hasher, earlySecret, "derived", emptyHash[:])
	handshakeSecret := hkdf.Extract(hasher, derivedSecret, sharedSecret)
	copy(hctx.clientHandshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "c hs traffic", trHash[:]))
	copy(hctx.serverHandshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "s hs traffic", trHash[:]))
	log.Printf("client handshake keys: %x\n", hctx.clientHandshakeTrafficSecret)
	log.Printf("server handshake keys: %x\n", hctx.serverHandshakeTrafficSecret)

	derivedSecret = deriveSecret(hasher, handshakeSecret, "derived", emptyHash[:])
	zeros := [32]byte{}
	masterSecret := hkdf.Extract(hasher, derivedSecret, zeros[:])
	copy(hctx.masterSecret[:], masterSecret)
	csecret := hctx.clientHandshakeTrafficSecret[:]
	ssecret := hctx.serverHandshakeTrafficSecret[:]
	copy(hctx.clientWriteKey[:], hkdf.ExpandLabel(hasher, csecret, "key", []byte{}, len(hctx.clientWriteKey)))
	copy(hctx.serverWriteKey[:], hkdf.ExpandLabel(hasher, ssecret, "key", []byte{}, len(hctx.serverWriteKey)))
	copy(hctx.clientWriteIV[:], hkdf.ExpandLabel(hasher, csecret, "iv", []byte{}, len(hctx.clientWriteIV)))
	copy(hctx.serverWriteIV[:], hkdf.ExpandLabel(hasher, ssecret, "iv", []byte{}, len(hctx.serverWriteIV)))
}

func deriveSecret(hasher hash.Hash, secret []byte, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hasher, secret, label, sum, len(sum))
}
