// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package receiver

/*
func (rc *Receiver) closeSomeConnectionsLocked() {
	for i := 0; i != constants.MaxCloseConnectionsPerDatagram; i++ { // arbitrary constant
		if rc.connPool.Len() == 0 || !rc.connPool.Front().InReceiverClosingQueue {
			return
		}
		conn := rc.connPool.PopFront()
		conn.InReceiverClosingQueue = false
		addr := conn.OnReceiverClose() // changes state to closed, sets addr to empty and returns previous addr
		//if _, ok := rc.connections[addr]; !ok {
		//	panic("address of closing connection must be in the map")
		//}
		delete(rc.connections, addr)
		rc.connPool.PushBack(conn)
	}
}

// called from any goroutine
func (rc *Receiver) AddToClosingQueue(conn *statemachine.ConnectionImpl, addr netip.AddrPort) {
	rc.connPoolMu.Lock()
	defer rc.connPoolMu.Unlock()
	if conn.InReceiverClosingQueue {
		return
	}
	conn.InReceiverClosingQueue = true
	rc.connPool.PushFront(conn)
}

func (rc *Receiver) popConnection(addr netip.AddrPort) *statemachine.ConnectionImpl {
	rc.connPoolMu.Lock()
	defer rc.connPoolMu.Unlock()

	rc.closeSomeConnectionsLocked()

	conn, ok := rc.connPool.TryPopBack()
	if !ok {
		if len(rc.connections)+rc.connPool.Len() >= rc.opts.MaxConnections {
			// TODO - send stateless datagram here, write to log
			return nil
		}
		conn = statemachine.NewServerConnection(addr)
	}
	if conn.InReceiverClosingQueue {
		panic("impossible, because closeSomeConnectionsLocked does at least 1 iteration")
	}
	if _, ok := rc.connections[addr]; ok {
		panic("address of reused connection must not be in the map")
	}
	rc.connections[addr] = conn
	return conn
}
*/
