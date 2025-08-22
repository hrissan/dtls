// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package transport

import (
	"errors"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/statemachine"
)

var ErrServerCannotStartConnection = errors.New("server can not start connection")

// blocks until socket is closed (externally)
func (t *Transport) goRunReceiverUDP(socket *net.UDPConn) {
	datagram := make([]byte, 65536)
	for {
		n, addr, err := socket.ReadFromUDPAddrPort(datagram)
		if n != 0 { // do not check for an error here
			t.opts.Stats.SocketReadDatagram(datagram[:n], addr)
			t.processDatagram(datagram[:n], addr)
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			t.opts.Stats.SocketReadError(n, addr, err)
			time.Sleep(t.opts.SocketReadErrorDelay)
		}
	}
}

func (t *Transport) processDatagram(datagram []byte, addr netip.AddrPort) {
	conn, err := t.processDatagramImpl(datagram, addr)
	if conn != nil {
		if err != nil {
			// TODO - return *dtlserrors.Error instead of error, so we cannot
			// return generic error by accident
			if dtlserrors.IsFatal(err) {
				log.Printf("fatal error: TODO - send alert and close connection: %v", err)
			} else {
				t.opts.Stats.Warning(addr, err)
			}
		} else {
			if conn.HasDataToSend() {
				// We postpone sending responses until full datagram processed
				t.snd.RegisterConnectionForSend(conn)
			}
		}
	} else {
		t.opts.Stats.Warning(addr, err)
		// TODO - alert is must here, otherwise client will not know we forgot their connection
	}
}

func (t *Transport) processDatagramImpl(datagram []byte, addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	// receiving goroutine owns rc.connections
	t.connPoolMu.Lock()
	conn := t.connections[addr]
	t.connPoolMu.Unlock()

	recordOffset := 0                  // Multiple DTLS records MAY be placed in a single datagram [rfc9147:4.3]
	for recordOffset < len(datagram) { // read records one by one
		fb := datagram[recordOffset]
		switch {
		case record.IsCiphertextRecord(fb):
			var hdr record.Ciphertext
			n, err := hdr.Parse(datagram[recordOffset:], t.opts.CIDLength)
			if err != nil {
				t.opts.Stats.BadRecord("ciphertext", recordOffset, len(datagram), addr, err)
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
			err = conn.ReceivedCiphertextRecord(t.opts, hdr)
			if dtlserrors.IsFatal(err) { // manual check in the loop, otherwise simply return
				return conn, err
			} else if err != nil {
				t.opts.Stats.Warning(addr, err)
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
				t.opts.Stats.BadRecord("plaintext", recordOffset, len(datagram), addr, err)
				// Anyone can send garbage, ignore.
				// We cannot continue to the next record.
				return conn, dtlserrors.WarnPlaintextRecordParsing
			}
			recordOffset += n
			// TODO - should we check/remove replayed received record sequence number?
			// how to do this without state?
			conn, err = t.receivedPlaintextRecord(conn, hdr, addr)
			if err != nil { // we do not believe plaintext, so only warnings
				t.opts.Stats.Warning(addr, err)
			}
			// Anyone can send garbage, ignore.
			// Error here does not conflict with our ability to process next record
			continue
		default:
			t.opts.Stats.BadRecord("unknown", recordOffset, len(datagram), addr, record.ErrRecordTypeFailedToParse)
			// Anyone can send garbage, ignore.
			// We cannot continue to the next record.
			return conn, dtlserrors.WarnUnknownRecordType
		}
	}
	return conn, nil
}

var ErrConnectionInProgress = errors.New("connection is in progress")

func (t *Transport) StartConnection(addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	t.connPoolMu.Lock()
	defer t.connPoolMu.Unlock()
	conn := t.connections[addr]
	if conn != nil {
		return nil, ErrConnectionInProgress // for now will wait for previous handshake timeout first
	} // TODO - if this is long going handshake, clear and start again?

	conn, err := statemachine.NewClientConnection(addr, t.opts)
	if err != nil {
		return nil, err
	}
	t.connections[addr] = conn
	return conn, nil
}
