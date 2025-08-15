package keys

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/hkdf"
)

type DirectionKeys struct {
	HandshakeTrafficSecret   [32]byte // we need to keep this for finished message
	ApplicationTrafficSecret [32]byte // we need to keep this for key update

	WriteIV [12]byte
	Write   cipher.AEAD  // 16 interface + 16 interface inside + 16 (counters) + 240 aes half + (240 aes half we do not need)
	SN      cipher.Block // 16 interface + 240 aes half + (240 aes half we do not need). Can be removed with unencrypted sequence numbers extension

	// for ServerHello retransmit and replay protection
	NextEpoch0Sequence  uint64 // TODO - reduce to uint16, this is for unencrypted client_hello/server_hello only
	Epoch               uint16
	NextSegmentSequence uint64

	// total size ~100 plus 240 (no seq encryption) or 480 (seq encryption)
	// but crypto.Block in standard golang's crypto contains both encrypting and decrypting halves,
	// so without unsafe tricks our direction keys total size is ~100 plus 480 (no seq encryption) or 960 (seq encryption)
}

func (keys *DirectionKeys) ComputeHandshakeKeys(serverKeys bool, handshakeSecret []byte, trHash []byte) {
	if keys.Epoch != 0 {
		panic("handshake keys state machine violation")
	}

	hasher := sha256.New()
	if serverKeys {
		copy(keys.HandshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "s hs traffic", trHash[:]))
		log.Printf("server2 handshake traffic secret: %x\n", keys.HandshakeTrafficSecret)
	} else {
		copy(keys.HandshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "c hs traffic", trHash[:]))
		log.Printf("client2 handshake traffic secret: %x\n", keys.HandshakeTrafficSecret)
	}
	keys.ComputeSymmetricKeys(keys.HandshakeTrafficSecret[:])

	keys.Epoch = 2
	keys.NextSegmentSequence = 0
}

// TODO - remove allocations
func (keys *DirectionKeys) ComputeFinished(hasher hash.Hash, transcriptHash []byte) []byte {
	finishedKey := hkdf.ExpandLabel(hasher, keys.HandshakeTrafficSecret[:], "finished", []byte{}, hasher.Size())
	//transcriptHash := sha256.Sum256(conn.transcript)
	return hkdf.HMAC(finishedKey, transcriptHash[:], hasher)
}

func (keys *DirectionKeys) ComputeApplicationTrafficSecret(serverKeys bool, masterSecret []byte, trHash []byte) {
	hasher := sha256.New()
	if serverKeys {
		copy(keys.ApplicationTrafficSecret[:], deriveSecret(hasher, masterSecret[:], "s ap traffic", trHash[:]))
		log.Printf("server2 application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	} else {
		copy(keys.ApplicationTrafficSecret[:], deriveSecret(hasher, masterSecret[:], "c ap traffic", trHash[:]))
		log.Printf("client2 application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	}
	// [rfc8446:7.2]
	//The next-generation application_traffic_secret is computed as:
	//
	//application_traffic_secret_N+1 =
	//	HKDF-Expand-Label(application_traffic_secret_N,
	//		"traffic upd", "", Hash.length)
}

func (keys *DirectionKeys) ComputeSymmetricKeys(secret []byte) {
	const keySize = 16 // TODO - should depend on cipher suite
	hasher := sha256.New()
	writeKey := hkdf.ExpandLabel(hasher, secret, "key", []byte{}, keySize)
	copy(keys.WriteIV[:], hkdf.ExpandLabel(hasher, secret, "iv", []byte{}, len(keys.WriteIV)))
	snKey := hkdf.ExpandLabel(hasher, secret, "sn", []byte{}, keySize)

	keys.Write = NewGCMCipher(NewAesCipher(writeKey))
	keys.SN = NewAesCipher(snKey)
}

func (keys *DirectionKeys) EncryptSequenceNumbers(seqNum []byte, cipherText []byte) error {
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
