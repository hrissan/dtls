package transport

import "time"

type TransportOptions struct {
	SocketReadErrorDelay   time.Duration
	SocketWriteErrorDelay  time.Duration
	CookieValidDuration    time.Duration
	HelloRetryQueueMaxSize int
}

func DefaultTransportOptions() TransportOptions {
	return TransportOptions{
		SocketReadErrorDelay:   50 * time.Millisecond,
		SocketWriteErrorDelay:  5 * time.Millisecond,
		CookieValidDuration:    120 * time.Second, // larger value for debug
		HelloRetryQueueMaxSize: 8192,
	}
}
