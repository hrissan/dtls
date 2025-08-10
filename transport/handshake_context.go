package transport

import "time"

type HandshakeContext struct {
	LastActivity time.Time // forget handshakes based on LRU
	ServerRandom [32]byte
	// for transport Receive/Send is more convenient than Client/Server
	NextMessageSeqReceive uint32
	NextMessageSeqSend    uint32
}
