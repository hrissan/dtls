package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/hkdf"
)

var ErrCipherTextTooShortForSNDecryption = errors.New("ciphertext too short for SN decryption")

type Keys struct {
	MasterSecret [32]byte

	Send    DirectionKeys
	Receive DirectionKeys

	ClientHandshakeTrafficSecret   [32]byte
	ServerHandshakeTrafficSecret   [32]byte
	ClientApplicationTrafficSecret [32]byte
	ServerApplicationTrafficSecret [32]byte

	ClientWriteKey [16]byte
	ServerWriteKey [16]byte
	ClientWriteIV  [12]byte
	ServerWriteIV  [12]byte
	ClientSNKey    [16]byte
	ServerSNKey    [16]byte

	DoNotEncryptSequenceNumbers bool // enabled extensions and saves us 50% memory on crypto contexts

	ClientWrite cipher.AEAD
	ServerWrite cipher.AEAD

	ClientSN cipher.Block
	ServerSN cipher.Block

	FailDeprotection uint64

	NextMessageSeqSend    uint16
	NextMessageSeqReceive uint16

	EpochReceive               uint16
	EpochSend                  uint16
	NextSegmentSequenceReceive uint64
	NextSegmentSequenceSend    uint64
	// for ServerHello retransmit and replay protection
	NextEpoch0SequenceReceive uint64
	NextEpoch0SequenceSend    uint64
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
	if keys.EpochSend != 0 || keys.EpochReceive != 0 {
		panic("handshake keys state machine violation")
	}

	hasher := sha256.New()
	emptyHash := sha256.Sum256(nil)

	salt := []byte{}
	psk := [32]byte{}
	earlySecret := hkdf.Extract(hasher, salt, psk[:])

	derivedSecret := deriveSecret(hasher, earlySecret, "derived", emptyHash[:])
	handshakeSecret := hkdf.Extract(hasher, derivedSecret, sharedSecret)

	keys.Send.ComputeHandshakeKeys(serverRole, handshakeSecret, trHash)
	keys.Receive.ComputeHandshakeKeys(!serverRole, handshakeSecret, trHash)

	copy(keys.ClientHandshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "c hs traffic", trHash))
	copy(keys.ServerHandshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "s hs traffic", trHash))
	log.Printf("client handshake traffic secret: %x\n", keys.ClientHandshakeTrafficSecret)
	log.Printf("server handshake traffic secret: %x\n", keys.ServerHandshakeTrafficSecret)

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
	copy(keys.ClientSNKey[:], hkdf.ExpandLabel(hasher, csecret, "sn", []byte{}, len(keys.ClientSNKey)))
	copy(keys.ServerSNKey[:], hkdf.ExpandLabel(hasher, ssecret, "sn", []byte{}, len(keys.ServerSNKey)))

	keys.ClientSN = NewAesCipher(keys.ClientSNKey[:])
	keys.ServerSN = NewAesCipher(keys.ServerSNKey[:])

	keys.ClientWrite = NewGCMCipher(NewAesCipher(keys.ClientWriteKey[:]))
	keys.ServerWrite = NewGCMCipher(NewAesCipher(keys.ServerWriteKey[:]))

	keys.EpochSend = 2
	keys.NextSegmentSequenceSend = 0
	keys.EpochReceive = 2
	keys.NextSegmentSequenceReceive = 0
}

func (keys *Keys) ComputeApplicationTrafficSecret(serverRole bool, trHash []byte) {
	keys.Send.ComputeApplicationTrafficSecret(serverRole, keys.MasterSecret[:], trHash)
	keys.Receive.ComputeApplicationTrafficSecret(!serverRole, keys.MasterSecret[:], trHash)
	hasher := sha256.New()
	copy(keys.ClientApplicationTrafficSecret[:], deriveSecret(hasher, keys.MasterSecret[:], "c ap traffic", trHash[:]))
	copy(keys.ServerApplicationTrafficSecret[:], deriveSecret(hasher, keys.MasterSecret[:], "s ap traffic", trHash[:]))
	log.Printf("client application traffic secret: %x\n", keys.ClientApplicationTrafficSecret)
	log.Printf("server application traffic secret: %x\n", keys.ServerApplicationTrafficSecret)
	// [rfc8446:7.2]
	//The next-generation application_traffic_secret is computed as:
	//
	//application_traffic_secret_N+1 =
	//	HKDF-Expand-Label(application_traffic_secret_N,
	//		"traffic upd", "", Hash.length)
}

func (keys *Keys) ComputeServerApplicationKeys() {
	hasher := sha256.New()
	ssecret := keys.ServerApplicationTrafficSecret[:]
	copy(keys.ServerWriteKey[:], hkdf.ExpandLabel(hasher, ssecret, "key", []byte{}, len(keys.ServerWriteKey)))
	copy(keys.ServerWriteIV[:], hkdf.ExpandLabel(hasher, ssecret, "iv", []byte{}, len(keys.ServerWriteIV)))
	//TODO - update epoch/seq
	//keys.Epoch = 3
	//keys.NextSegmentSequenceReceive = 0
}

func (keys *Keys) ComputeClientApplicationKeys() {
	hasher := sha256.New()
	csecret := keys.ClientApplicationTrafficSecret[:]
	copy(keys.ClientWriteKey[:], hkdf.ExpandLabel(hasher, csecret, "key", []byte{}, len(keys.ClientWriteKey)))
	copy(keys.ClientWriteIV[:], hkdf.ExpandLabel(hasher, csecret, "iv", []byte{}, len(keys.ClientWriteIV)))
	//TODO - update epoch/seq
	//keys.Epoch = 3
	//keys.NextSegmentSequenceReceive = 0
}

func deriveSecret(hasher hash.Hash, secret []byte, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hasher, secret, label, sum, len(sum))
}

// TODO - remove allocations
func (keys *Keys) ComputeClientFinished(hasher hash.Hash, transcriptHash []byte) []byte {
	finishedKey := hkdf.ExpandLabel(hasher, keys.ClientHandshakeTrafficSecret[:], "finished", []byte{}, hasher.Size())
	//transcriptHash := sha256.Sum256(conn.transcript)
	return hkdf.HMAC(finishedKey, transcriptHash[:], hasher)
}

// TODO - remove allocations
func (keys *Keys) ComputeServerFinished(hasher hash.Hash, transcriptHash []byte) []byte {
	finishedKey := hkdf.ExpandLabel(hasher, keys.ServerHandshakeTrafficSecret[:], "finished", []byte{}, hasher.Size())
	//transcriptHash := sha256.Sum256(conn.transcript)
	return hkdf.HMAC(finishedKey, transcriptHash[:], hasher)
}

// panic if len(iv) is < 8
func (keys *Keys) FillIVSequence(iv []byte, seq uint64) {
	maskBytes := iv[len(iv)-8:]
	mask := binary.BigEndian.Uint64(maskBytes)
	binary.BigEndian.PutUint64(maskBytes, seq^mask)
}
