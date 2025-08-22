// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package receiver

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/dtls/circular"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
	"github.com/hrissan/dtls/transport/sender"
	"github.com/hrissan/dtls/transport/statemachine"
)

var ErrServerCannotStartConnection = errors.New("server can start connection")

// Receiver also performs stateless logic
type Receiver struct {
	opts        *options.TransportOptions
	cookieState cookie.CookieState
	snd         *sender.Sender

	connPoolMu sync.Mutex
	// closed connections are at the back
	// closing connections are at the front,
	// so we can close connections 1 by 1, by looking at the front,
	// closing, and putting to the back
	connPool circular.Buffer[*statemachine.ConnectionImpl]

	// owned by receiving goroutine
	// only ClientHello with correct cookie and larger timestamp replaces
	// previous handshake or connection here [rfc9147:5.11]
	connections map[netip.AddrPort]*statemachine.ConnectionImpl

	// TODO - limit on max number of parallel handshakes, clear items by LRU
}

func NewReceiver(opts *options.TransportOptions, snd *sender.Sender) *Receiver {
	rc := &Receiver{
		opts: opts,
		snd:  snd,
	}
	rc.cookieState.SetRand(opts.Rnd)
	if opts.Preallocate {
		rc.connections = make(map[netip.AddrPort]*statemachine.ConnectionImpl, opts.MaxConnections)
		rc.connPool.Reserve(opts.MaxConnections)
	} else {
		rc.connections = map[netip.AddrPort]*statemachine.ConnectionImpl{}
	}
	return rc
}

// socket must be closed by socket owner (externally)
func (rc *Receiver) Close() {
}

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

// blocks until socket is closed (externally)
func (rc *Receiver) GoRunUDP(socket *net.UDPConn) {
	datagram := make([]byte, 65536)
	for {
		n, addr, err := socket.ReadFromUDPAddrPort(datagram)
		if n != 0 { // do not check for an error here
			rc.opts.Stats.SocketReadDatagram(datagram[:n], addr)
			rc.processDatagram(datagram[:n], addr)
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			rc.opts.Stats.SocketReadError(n, addr, err)
			time.Sleep(rc.opts.SocketReadErrorDelay)
		}
	}
}

func (rc *Receiver) processDatagram(datagram []byte, addr netip.AddrPort) {
	conn, err := rc.processDatagramImpl(datagram, addr)
	if conn != nil {
		if err != nil {
			// TODO - return *dtlserrors.Error instead of error, so we cannot
			// return generic error by accident
			if dtlserrors.IsFatal(err) {
				log.Printf("fatal error: TODO - send alert and close connection: %v", err)
			} else {
				rc.opts.Stats.Warning(addr, err)
			}
		} else {
			if conn.HasDataToSend() {
				// We postpone sending responses until full datagram processed
				rc.snd.RegisterConnectionForSend(conn)
			}
		}
	} else {
		rc.opts.Stats.Warning(addr, err)
		// TODO - alert is must here, otherwise client will not know we forgot their connection
	}
}

func (rc *Receiver) processDatagramImpl(datagram []byte, addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	// receiving goroutine owns rc.connections
	rc.connPoolMu.Lock()
	conn := rc.connections[addr]
	rc.connPoolMu.Unlock()

	recordOffset := 0                  // Multiple DTLS records MAY be placed in a single datagram [rfc9147:4.3]
	for recordOffset < len(datagram) { // read records one by one
		fb := datagram[recordOffset]
		switch {
		case record.IsCiphertextRecord(fb):
			var hdr record.Ciphertext
			n, err := hdr.Parse(datagram[recordOffset:], rc.opts.CIDLength)
			if err != nil {
				rc.opts.Stats.BadRecord("ciphertext", recordOffset, len(datagram), addr, err)
				// Anyone can send garbage, ignore.
				// We cannot continue to the next record.
				return conn, dtlserrors.WarnCiphertextRecordParsing
			}
			recordOffset += n
			// log.Printf("dtls: got ciphertext %v cid(hex): %x from %v, body(hex): %x", hdr., cid, addr, body)
			if conn == nil {
				// We can continue. but we do not, most likely there is more encrypted records
				return conn, dtlserrors.WarnCiphertextNoConnection
			}
			err = conn.ReceivedCiphertextRecord(rc.opts, hdr)
			if dtlserrors.IsFatal(err) { // manual check in the loop, otherwise simply return
				return conn, err
			} else if err != nil {
				rc.opts.Stats.Warning(addr, err)
			}
			// Minor problems inside record do not conflict with our ability to process next record
			continue
		case fb == record.RecordTypeAlert ||
			fb == record.RecordTypeHandshake ||
			fb == record.RecordTypeAck:
			// [rfc9147:4.1], but it seems acks must always be encrypted in DTLS1.3?
			// TODO - contact DTLS team to clarify standard
			var hdr record.Plaintext
			n, err := hdr.Parse(datagram[recordOffset:])
			if err != nil {
				rc.opts.Stats.BadRecord("plaintext", recordOffset, len(datagram), addr, err)
				// Anyone can send garbage, ignore.
				// We cannot continue to the next record.
				return conn, dtlserrors.WarnPlaintextRecordParsing
			}
			recordOffset += n
			// TODO - should we check/remove replayed received record sequence number?
			// how to do this without state?
			conn, err = rc.receivedPlaintextRecord(conn, hdr, addr)
			if err != nil { // we do not believe plaintext, so only warnings
				rc.opts.Stats.Warning(addr, err)
			}
			// Anyone can send garbage, ignore.
			// Error here does not conflict with our ability to process next record
			continue
		default:
			rc.opts.Stats.BadRecord("unknown", recordOffset, len(datagram), addr, record.ErrRecordTypeFailedToParse)
			// Anyone can send garbage, ignore.
			// We cannot continue to the next record.
			return conn, dtlserrors.WarnUnknownRecordType
		}
	}
	return conn, nil
}

func (rc *Receiver) StartConnection(peerAddr netip.AddrPort) error {
	if rc.opts.RoleServer {
		return ErrServerCannotStartConnection
	}
	hctxToSend, err := rc.startConnection(peerAddr)
	if hctxToSend != nil { // motivation: do not register under our lock
		rc.snd.RegisterConnectionForSend(hctxToSend)
	}
	return err
}

var ErrConnectionInProgress = errors.New("connection is in progress")

func (rc *Receiver) startConnection(addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	rc.connPoolMu.Lock()
	defer rc.connPoolMu.Unlock()
	conn := rc.connections[addr]
	if conn != nil {
		return nil, ErrConnectionInProgress // for now will wait for previous handshake timeout first
	} // TODO - if this is long going handshake, clear and start again?

	conn, err := statemachine.NewClientConnection(addr, rc.opts)
	if err != nil {
		return nil, err
	}
	rc.connections[addr] = conn
	return conn, nil
}
