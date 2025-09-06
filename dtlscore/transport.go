// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"net/netip"
	"sync"

	"github.com/hrissan/dtls/circular"
	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/record"
)

type Transport struct {
	opts        *Options
	handler     TransportHandler
	cookieState cookie.CookieState
	snd         Sender

	// Each connection is either
	// 1. closed, not in map, in the pool
	// 2. closed, not in map, will be added to the pool very soon by sender
	// 3. !closed, in the map, not in the pool
	// To make this possible, order of locks is
	// transport.Lock() // normal lookup of connection (per datagram)
	// conn.Lock(), transport.Lock()  // for adding/removing to the map and adding to the pool
	// transport.Lock() // for removing from the pool
	//

	// ClientHello with correct cookie and larger timestamp replaces
	// previous handshake or established connection here [rfc9147:5.11].
	mu                 sync.Mutex
	connMap            map[netip.AddrPort]*Connection
	connPool           circular.Buffer[*Connection]
	createdConnections int // some are in pool, others are somewhere else
	shutdown           bool

	// TODO - limit on max number of parallel handshakes, clear items by LRU
}

func NewTransport(opts *Options, snd Sender, handler TransportHandler) *Transport {
	t := &Transport{
		opts:    opts,
		snd:     snd,
		handler: handler,
	}
	t.cookieState.SetRand(opts.Rnd)
	if opts.Preallocate {
		t.connMap = make(map[netip.AddrPort]*Connection, opts.MaxConnections)
		if t.opts.RoleServer {
			t.connPool.Reserve(opts.MaxConnections)
		}
	} else {
		t.connMap = map[netip.AddrPort]*Connection{}
	}
	return t
}

func (t *Transport) Options() *Options {
	return t.opts
}

// send notify to all connections, close socket
func (t *Transport) Shutdown() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.shutdown = true
	for _, conn := range t.connMap {
		conn.Shutdown(record.Alert{Level: record.AlerLevelFatal, Description: 0}) // close_notify
	}
	t.snd.Shutdown()
}

func (t *Transport) getFromPool() *Connection {
	conn, ok := t.getFromPoolLocked()
	if !ok {
		return nil
	}
	if conn != nil {
		return conn
	}
	var ha ConnectionHandler
	conn, ha = t.handler.OnNewConnection()
	// no race setting handler and snd, because connection is a new one
	conn.handler = ha
	conn.tr = t
	return conn
}

func (t *Transport) getFromPoolLocked() (*Connection, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn, ok := t.connPool.TryPopBack()
	if ok {
		return conn, true
	}
	if t.createdConnections >= t.opts.MaxConnections {
		return nil, false
	}
	t.createdConnections++
	return nil, true // will be created without lock
}

// call under connection's mutex to maintain state invariant that
// closed connections are not in the map, while !closed are in the map
func (t *Transport) addToMap(conn *Connection, addr netip.AddrPort) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.connMap[addr]; ok {
		panic("connection magically appeared in the map")
	}
	t.connMap[addr] = conn
}

// call under connection's mutex to maintain state invariant that
// closed connections are not in the map, while !closed are in the map
func (t *Transport) removeFromMap(conn *Connection, addr netip.AddrPort, returnToPool bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c2, ok := t.connMap[addr]
	if !ok || c2 != conn {
		panic("connection magically replaced in the map")
	}
	delete(t.connMap, addr)
	if returnToPool {
		if t.opts.RoleServer { // For now, reuse connections on server only
			t.connPool.PushBack(conn)
		} else {
			t.createdConnections--
		}
	}
}
