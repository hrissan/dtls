package keys

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"log"

	"github.com/hrissan/tinydtls/hkdf"
	"github.com/hrissan/tinydtls/record"
)

var ErrCipherTextAllZeroPadding = errors.New("ciphertext all zero padding")

type DirectionKeys struct {
	// fields sorted to minimize padding
	ApplicationTrafficSecret [32]byte // we need to keep this for key update

	Symmetric SymmetricKeys

	// total size ~100 plus 240 (no seq encryption) or 480 (seq encryption)
	// but crypto.Block in standard golang's crypto contains both encrypting and decrypting halves,
	// so without unsafe tricks our direction keys total size is ~100 plus 480 (no seq encryption) or 960 (seq encryption)
}

func (keys *DirectionKeys) ComputeHandshakeKeys(serverKeys bool, handshakeSecret []byte, trHash []byte) (handshakeTrafficSecret [32]byte) {
	if keys.Symmetric.Epoch != 0 {
		panic("handshake keys state machine violation")
	}

	hasher := sha256.New()
	if serverKeys {
		copy(handshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "s hs traffic", trHash[:]))
		log.Printf("server2 handshake traffic secret: %x\n", handshakeTrafficSecret)
	} else {
		copy(handshakeTrafficSecret[:], deriveSecret(hasher, handshakeSecret, "c hs traffic", trHash[:]))
		log.Printf("client2 handshake traffic secret: %x\n", handshakeTrafficSecret)
	}
	keys.Symmetric.ComputeKeys(handshakeTrafficSecret[:])

	keys.Symmetric.Epoch = 2
	return handshakeTrafficSecret
}

// TODO - remove allocations
func (keys *DirectionKeys) ComputeFinished(hasher hash.Hash, HandshakeTrafficSecret []byte, transcriptHash []byte) []byte {
	finishedKey := hkdf.ExpandLabel(hasher, HandshakeTrafficSecret, "finished", []byte{}, hasher.Size())
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

func (keys *DirectionKeys) ComputeNextApplicationTrafficSecret(serverKeys bool) {
	hasher := sha256.New()
	copy(keys.ApplicationTrafficSecret[:], hkdf.ExpandLabel(hasher, keys.ApplicationTrafficSecret[:], "traffic upd", []byte{}, len(keys.ApplicationTrafficSecret)))
	if serverKeys {
		log.Printf("server next application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	} else {
		log.Printf("client next application traffic secret: %x\n", keys.ApplicationTrafficSecret)
	}
}

// contentType is the first non-zero byte from the end
func findPaddingOffsetContentType(data []byte) (paddingOffset int, contentType byte) {
	offset := len(data)
	for ; offset > 16; offset -= 16 {
		if binary.LittleEndian.Uint64(data[offset-16:]) != 0 {
			break
		}
		if binary.LittleEndian.Uint64(data[offset-8:]) != 0 {
			break
		}
	}
	for ; offset > 0; offset-- {
		b := data[offset-1]
		if b != 0 {
			return offset - 1, b
		}
	}
	return -1, 0
}

// Warning - decrypts in place, seqNumData and body can be garbage after unsuccessfull decryption
func (keys *SymmetricKeys) Deprotect(hdr record.Ciphertext, encryptSN bool, expectedSN uint64) (decrypted []byte, seq uint64, contentType byte, err error) {
	if encryptSN {
		if err := keys.EncryptSequenceNumbers(hdr.SeqNum, hdr.Body); err != nil {
			return nil, 0, 0, err
		}
	}
	gcm := keys.Write
	iv := keys.WriteIV // copy, otherwise disaster
	decryptedSeqData, seq := hdr.ClosestSequenceNumber(hdr.SeqNum, expectedSN)
	log.Printf("decrypted SN: %d, closest: %d", decryptedSeqData, seq)

	FillIVSequence(iv[:], seq)
	decrypted, err = gcm.Open(hdr.Body[:0], iv[:], hdr.Body, hdr.Header)
	if err != nil {
		return nil, seq, 0, err
	}
	paddingOffset, contentType := findPaddingOffsetContentType(decrypted) // [rfc8446:5.4]
	if paddingOffset < 0 {
		// TODO - send alert
		return nil, seq, 0, ErrCipherTextAllZeroPadding
	}
	return decrypted[:paddingOffset], seq, contentType, nil
}
