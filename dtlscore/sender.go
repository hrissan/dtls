// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"net/netip"

	"github.com/hrissan/dtls/constants"
)

// all sender methods are called by transport and must not be called by user code
type Sender interface {
	// returns datagram from the storage pool or nil if pool is empty
	PopHelloRetryDatagramStorage() *[constants.MaxOutgoingHRRDatagramLength]byte
	// sends datagram and put datagram to the pool
	SendHelloRetryDatagram(data *[constants.MaxOutgoingHRRDatagramLength]byte, size int, addr netip.AddrPort)
	// adds connection to the send queue (with no duplicates)
	RegisterConnectionForSend(conn *Connection)
	// stops adding connections to the send queue
	Shutdown()
}
