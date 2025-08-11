package transport

import (
	"hash"
	"time"
)

type HandshakeContext struct {
	LastActivity time.Time // forget handshakes based on LRU

	MessagesSendQueue [][]byte

	MessageToReceiveSet bool // if set, has seq == NextMessageSeqReceive-1
	MessageToReceive    []byte

	TranscriptHasher hash.Hash
}
