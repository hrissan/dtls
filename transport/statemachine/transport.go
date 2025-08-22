// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"net"
	"net/netip"
	"sync"

	"github.com/hrissan/dtls/circular"
	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/transport/options"
)

type Transport struct {
	opts        *options.TransportOptions
	cookieState cookie.CookieState
	snd         *sender

	connPoolMu sync.Mutex
	// closed connections are at the back
	// closing connections are at the front,
	// so we can close connections 1 by 1, by looking at the front,
	// closing, and putting to the back
	connPool circular.Buffer[*Connection]

	// owned by receiving goroutine
	// only ClientHello with correct cookie and larger timestamp replaces
	// previous handshake or connection here [rfc9147:5.11]
	connections map[netip.AddrPort]*Connection

	// TODO - limit on max number of parallel handshakes, clear items by LRU
}

func NewTransport(opts *options.TransportOptions) *Transport {
	snd := newSender(opts)
	t := &Transport{
		opts: opts,
		snd:  snd,
	}
	t.cookieState.SetRand(opts.Rnd)
	if opts.Preallocate {
		t.connections = make(map[netip.AddrPort]*Connection, opts.MaxConnections)
		t.connPool.Reserve(opts.MaxConnections)
	} else {
		t.connections = map[netip.AddrPort]*Connection{}
	}
	return t
}

// socket must be closed by socket owner (externally)
func (t *Transport) Options() *options.TransportOptions {
	return t.opts
}

// socket must be closed by socket owner (externally)
func (t *Transport) Close() {
	t.snd.Close()
}

// blocks until socket is closed (externally)
func (t *Transport) GoRunUDP(socket *net.UDPConn) {
	ch := make(chan struct{})
	go func() {
		t.snd.GoRunUDP(socket)
		ch <- struct{}{}
	}()
	t.goRunReceiverUDP(socket)
	<-ch
}
