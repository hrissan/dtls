package transport

import (
	"hash"
	"time"
)

type HandshakeContext struct {
	LastActivity time.Time // forget handshakes based on LRU
	ServerRandom [32]byte
	x25519Secret [32]byte

	NextMessageSeqSend uint32
	MessagesSendQueue  [][]byte

	NextMessageSeqReceive uint32
	MessageToReceiveSet   bool // if set, has seq == NextMessageSeqReceive-1
	MessageToReceive      []byte

	TranscriptHasher hash.Hash
}
