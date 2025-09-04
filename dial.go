// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtls

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/hrissan/dtls/transport/statemachine"
)

func Dial(t *statemachine.Transport, network, address string) (*Conn, error) {
	return DialTimeout(t, network, address, 0)
}

func DialTimeout(t *statemachine.Transport, network, address string, timeout time.Duration) (*Conn, error) {
	return DialTimeoutEarlyData(t, network, address, timeout, nil)
}

func DialTimeoutEarlyData(t *statemachine.Transport, network, address string, timeout time.Duration, earlyData []byte) (*Conn, error) {
	netipAddr, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	netAddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	conn := newConn(netAddr, netAddr)
	if len(earlyData) != 0 {
		conn.writing = append(conn.writing, append([]byte{}, earlyData...))
	}
	err = t.StartConnection(&conn.tc, conn, netipAddr)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	select {
	case <-conn.condDial:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
