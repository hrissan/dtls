package options

import (
	"time"

	"github.com/hrissan/tinydtls/dtlsrand"
	"github.com/hrissan/tinydtls/transport/stats"
)

type TransportOptions struct {
	RoleServer bool
	Rnd        dtlsrand.Rand
	Stats      stats.Stats

	SocketReadErrorDelay   time.Duration
	SocketWriteErrorDelay  time.Duration
	CookieValidDuration    time.Duration
	HelloRetryQueueMaxSize int
	CIDLength              int // We use fixed size connection ID, so we can parse ciphertext records easily [rfc9147:9.1]
}

func DefaultTransportOptions(roleServer bool, rnd dtlsrand.Rand, stats stats.Stats) *TransportOptions {
	return &TransportOptions{
		RoleServer:             roleServer,
		Rnd:                    rnd,
		Stats:                  stats,
		SocketReadErrorDelay:   50 * time.Millisecond,
		SocketWriteErrorDelay:  5 * time.Millisecond,
		CookieValidDuration:    120 * time.Second, // larger value for debug
		HelloRetryQueueMaxSize: 8192,
		CIDLength:              0,
	}
}
