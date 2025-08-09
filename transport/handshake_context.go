package transport

import "time"

type HandshakeContext struct {
	LastActivity time.Time // forget handshakes based on LRU
}
