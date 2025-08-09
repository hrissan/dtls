package transport

import "time"

type HandshakeContext struct {
	LastActivity   time.Time // forget handshakes based on LRU
	ServerRandom   [32]byte
	NextMessageSeq uint32
}
