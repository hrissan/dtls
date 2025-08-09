package transport

import "time"

type TransportOptions struct {
	SocketReadErrorDelay  time.Duration
	SocketWriteErrorDelay time.Duration
	HelloRetryQueueSize   int
}

func DefaultTransportOptions() TransportOptions {
	return TransportOptions{
		SocketReadErrorDelay:  50 * time.Millisecond,
		SocketWriteErrorDelay: 5 * time.Millisecond,
		HelloRetryQueueSize:   8192,
	}
}
