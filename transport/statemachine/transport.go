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
	handler     TransportHandler
	cookieState cookie.CookieState
	snd         *sender

	// Connections are either in the map, or in the pool.
	// New connections behave exactly as those from the pool
	// So, connection starts in the pool in "closed" state.
	// Then, when receiver receives ClientHello2, it will skip it if connection
	// is in the map already (for now, we'll learn how to replace connections soon).
	// But if connection is not in the map, it will put it into the map, and change
	// connection state to anything, except "shutting down" or "closed".
	// Then connection will live in the map until it's shutdown method will eb called,
	// then connection will change state to the "shutting down" and register in the sender.
	// Sender then will trigger, call OnDisconnect method (setting state to "closed"),
	// then sender will move connection from the map into the pool.
	//
	// [in pool, closed] -> (receiver processing ClientHello) ->
	// [in map, running] -> (shutdown) ->
	// [in map, shutdown] -> (sender's OnDisconnect) ->
	// [in map, closed] -> (sender moving to pool) -> [in pool, closed]
	//
	// also we have sub path, when replacing connection with ClientHello2
	// [in map, running] -> (receiver calling OnDisconnect) ->
	// [in map, closed] -> (receiver continuing ClientHello) -> [in map, running]

	// ClientHello with correct cookie and larger timestamp replaces
	// previous handshake or established connection here [rfc9147:5.11].
	mu          sync.Mutex
	connections map[netip.AddrPort]*Connection
	connPool    circular.Buffer[*Connection]

	// TODO - limit on max number of parallel handshakes, clear items by LRU
}

func NewTransport(opts *options.TransportOptions, handler TransportHandler) *Transport {
	t := &Transport{
		opts:    opts,
		handler: handler,
	}
	t.snd = newSender(t)
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

func (t *Transport) removeConnection(conn *Connection, addr netip.AddrPort) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connections[addr] != conn {
		panic("closed connections reuse invariant violated")
	}
	t.connections[addr] = nil
	t.connPool.PushBack(conn)
}

func (t *Transport) returnToPool(conn *Connection, addr netip.AddrPort) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !conn.inMap {
		return
	}
	conn.inMap = false
	t.connections[addr] = nil
	t.connPool.PushBack(conn)
}

func (t *Transport) addToMapFromPool(addr netip.AddrPort) *Connection {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.connections[addr]; ok {
		panic("connection magically appeared in the map")
	}
	conn, ok := t.connPool.TryPopBack()
	if !ok {
		var ha ConnectionHandler
		conn, ha = t.handler.OnNewConnection()
		// no race setting handler and snd, because connection is the new one
		conn.handler = ha
		conn.snd = t.snd
	}
	if conn.inMap {
		panic("new connection or connection from the pool must not be in the map")
	}
	conn.inMap = true
	t.connections[addr] = conn
	return conn
}
