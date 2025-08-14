package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/hkdf"
	"golang.org/x/crypto/curve25519"
)

var ErrCipherTextTooShortForSNDecryption = errors.New("ciphertext too short for SN decryption")

type Keys struct {
	LocalRandom  [32]byte // TODO - move to handshake context
	X25519Secret [32]byte // TODO - move to handshake context
	X25519Public [32]byte // TODO - move to handshake context

	ClientHandshakeTrafficSecret [32]byte
	ServerHandshakeTrafficSecret [32]byte

	MasterSecret [32]byte

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

	Epoch                      uint16
	NextSegmentSequenceReceive uint64
	NextSegmentSequenceSend    uint64
	NextEpoch0SequenceReceive  uint64 // to retransmit ServerHello we must remember separate epoch 0 sequence
}

func (keys *Keys) EncryptSequenceNumbers(seqNum []byte, cipherText []byte, roleServer bool) error {
	var mask [32]byte // Some space good for many ciphers, TODO - check constant mush earlier
	if !keys.DoNotEncryptSequenceNumbers {
		snCipher := keys.ServerSN
		if roleServer {
			snCipher = keys.ClientSN
		}
		if len(cipherText) < snCipher.BlockSize() {
			// TODO - generate alert
			return ErrCipherTextTooShortForSNDecryption
		}
		snCipher.Encrypt(mask[:], cipherText)
	}
	if len(seqNum) == 1 {
		seqNum[0] ^= mask[0]
		log.Printf("decrypted SN: %d", uint16(seqNum[0]))
		return nil
	} else if len(seqNum) == 2 {
		seqNum[0] ^= mask[0]
		seqNum[1] ^= mask[1]
		log.Printf("decrypted SN: %d", binary.BigEndian.Uint16(seqNum))
		return nil
	} else {
		panic("seqNum must have 1 or 2 bytes")
	}
}

func (keys *Keys) ComputeKeyShare(rnd dtlsrand.Rand) {
	rnd.Read(keys.X25519Secret[:])
	{
		x25519Public, err := curve25519.X25519(keys.X25519Secret[:], curve25519.Basepoint)
		if err != nil {
			panic("curve25519.X25519 failed")
		}
		copy(keys.X25519Public[:], x25519Public)
	}
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
	copy(keys.ClientSNKey[:], hkdf.ExpandLabel(hasher, csecret, "sn", []byte{}, len(keys.ClientSNKey)))
	copy(keys.ServerSNKey[:], hkdf.ExpandLabel(hasher, ssecret, "sn", []byte{}, len(keys.ServerSNKey)))

	keys.ClientSN = NewAesCipher(keys.ClientSNKey[:])
	keys.ServerSN = NewAesCipher(keys.ServerSNKey[:])

	keys.ClientWrite = NewGCMCipher(NewAesCipher(keys.ClientWriteKey[:]))
	keys.ServerWrite = NewGCMCipher(NewAesCipher(keys.ServerWriteKey[:]))

	keys.Epoch = 2
	//os.Exit(1) // to compare printed keys above
}

func deriveSecret(hasher hash.Hash, secret []byte, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hasher, secret, label, sum, len(sum))
}

func (keys *Keys) ComputeClientFinished(hasher hash.Hash, transcriptHash []byte) []byte {
	finishedKey := hkdf.ExpandLabel(hasher, keys.ClientHandshakeTrafficSecret[:], "finished", []byte{}, hasher.Size())
	//transcriptHash := sha256.Sum256(conn.transcript)
	return hkdf.HMAC(finishedKey, transcriptHash[:], hasher)
}

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
