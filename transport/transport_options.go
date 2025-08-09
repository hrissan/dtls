package transport

import "time"

type TransportOptions struct {
	SocketReadErrorDelay time.Duration
	HelloRetryQueueSize  int
}
