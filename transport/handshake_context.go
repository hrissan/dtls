package transport

import (
	"hash"
	"time"
)

type HandshakeContext struct {
	LastActivity time.Time // forget handshakes based on LRU
	ServerRandom [32]byte
	x25519Secret [32]byte

	clientHandshakeTrafficSecret [32]byte
	serverHandshakeTrafficSecret [32]byte

	masterSecret [32]byte

	clientWriteKey [16]byte
	serverWriteKey [16]byte
	clientWriteIV  [12]byte
	serverWriteIV  [12]byte

	NextMessageSeqSend uint32
	MessagesSendQueue  [][]byte

	NextMessageSeqReceive uint32
	MessageToReceiveSet   bool // if set, has seq == NextMessageSeqReceive-1
	MessageToReceive      []byte

	TranscriptHasher hash.Hash
}
