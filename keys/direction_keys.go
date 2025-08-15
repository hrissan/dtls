package keys

import (
	"crypto/sha256"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/hkdf"
)

type DirectionKeys struct {
	// fields sorted to minimize padding
	HandshakeTrafficSecret   [32]byte // we need to keep this for finished message. TODO - move into HandshakeContext
	ApplicationTrafficSecret [32]byte // we need to keep this for key update

	// for ServerHello retransmit and replay protection
	NextEpoch0Sequence  uint64 // cannot reduce this, due to 48-bit value on the wire, this is for unencrypted client_hello/server_hello only, but peer can select very large value
	NextSegmentSequence uint64

	Symmetric SymmetricKeys

	// total size ~100 plus 240 (no seq encryption) or 480 (seq encryption)
	// but crypto.Block in standard golang's crypto contains both encrypting and decrypting halves,
	// so without unsafe tricks our direction keys total size is ~100 plus 480 (no seq encryption) or 960 (seq encryption)
}

func (keys *DirectionKeys) ComputeHandshakeKeys(serverKeys bool, handshakeSecret []byte, trHash []byte) {
	if keys.Symmetric.Epoch != 0 {
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
	keys.Symmetric.ComputeKeys(keys.HandshakeTrafficSecret[:])

	keys.Symmetric.Epoch = 2
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
