package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/format"
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

	ClientSN cipher.Block
	ServerSN cipher.Block

	NextMessageSeqSend    uint32
	NextMessageSeqReceive uint32

	Epoch               uint16
	NextSegmentSequence uint64
	NextEpoch0Sequence  uint64 // to retransmit ServerHello we must remember separate epoch 0 sequence
}

func (keys *Keys) EncryptSequenceNumbers(hdr *format.CiphertextRecordHeader, cipherText []byte, roleServer bool) error {
	if keys.DoNotEncryptSequenceNumbers {
		return nil
	}
	snCipher := keys.ServerSN
	if roleServer {
		snCipher = keys.ClientSN
	}
	if len(cipherText) < snCipher.BlockSize() {
		// TODO - generate alert
		return ErrCipherTextTooShortForSNDecryption
	}
	var mask [64]byte // Some space good for many ciphers, TODO - check constant mush earlier
	snCipher.Encrypt(mask[:], cipherText)
	hdr.SequenceNumberBytes[0] ^= mask[0]
	hdr.SequenceNumberBytes[1] ^= mask[1]
	log.Printf("decrypting SN: %x %d", hdr.SequenceNumberBytes[:], hdr.SequenceNumber())
	return nil
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

	c, err := aes.NewCipher(keys.ClientSNKey[:])
	if err != nil {
		panic("aes.NewCipher failed")
	}
	keys.ClientSN = c
	c, err = aes.NewCipher(keys.ServerSNKey[:])
	if err != nil {
		panic("aes.NewCipher failed")
	}
	keys.ServerSN = c

	keys.Epoch = 2
	//os.Exit(1) // to compare printed keys above
}

func deriveSecret(hasher hash.Hash, secret []byte, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hasher, secret, label, sum, len(sum))
}
