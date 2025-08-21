// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package receiver

import (
	"log"
	"net/netip"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/statemachine"
)

func (rc *Receiver) receivedPlaintextRecord(conn *statemachine.ConnectionImpl, hdr record.Plaintext, addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	switch hdr.ContentType {
	case record.RecordTypeAlert:
		if conn == nil { // Will not respond with alert, otherwise endless cycle
			return conn, nil
		}
		return conn, conn.ReceivedAlert(false, hdr.Body)
	case record.RecordTypeAck:
		log.Printf("dtls: got ack record (plaintext) %d bytes from %v, message(hex): %x", len(hdr.Body), addr, hdr.Body)
		// unencrypted acks can only acknowledge unencrypted messaged, so very niche, we simply ignore them
	case record.RecordTypeHandshake:
		return rc.receivedPlaintextHandshake(conn, hdr, addr)
	}
	panic("unreacheable due to check in caller")
}

func (rc *Receiver) receivedPlaintextHandshake(conn *statemachine.ConnectionImpl, hdr record.Plaintext, addr netip.AddrPort) (*statemachine.ConnectionImpl, error) {
	// log.Printf("dtls: got handshake record (plaintext) %d bytes from %v, message(hex): %x", len(recordData), addr, recordData)
	if len(hdr.Body) == 0 {
		// [rfc8446:5.1] Implementations MUST NOT send zero-length fragments of Handshake types, even if those fragments contain padding
		return conn, dtlserrors.ErrHandshakeRecordEmpty
	}
	messageOffset := 0
	// there are two acceptable ways to pack two DTLS handshake messages into the same datagram:
	// in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(hdr.Body) {
		// log.Printf("dtls: got handshake message %v from %v, message(hex): %x", hdr, addr, messageData)
		var fragment handshake.Fragment
		n, err := fragment.Parse(hdr.Body[messageOffset:])
		if err != nil {
			// we cannot continue to the next fragment.
			return conn, dtlserrors.WarnPlaintextHandshakeMessageHeaderParsing
		}
		messageOffset += n
		// on error below we could continue to the next fragment,
		// but state machine will be broken anyway, so we return
		switch fragment.Header.MsgType {
		case handshake.MsgTypeClientHello:
			if fragment.Header.IsFragmented() {
				return conn, dtlserrors.WarnClientHelloFragmented
			}
			msg := handshake.Message{
				MsgType: fragment.Header.MsgType,
				MsgSeq:  fragment.Header.MsgSeq,
				Body:    fragment.Body,
			}
			conn, err = rc.receivedClientHello(conn, msg, addr)
			if err != nil {
				return conn, err
			}
		case handshake.MsgTypeServerHello:
			if conn == nil {
				return conn, dtlserrors.ErrServerHelloNoActiveConnection
			}
			return conn, conn.ReceivedServerHelloFragment(rc.opts, fragment, record.NumberWith(0, hdr.SequenceNumber))
		default:
			rc.opts.Stats.MustBeEncrypted("handshake", handshake.MsgTypeToName(fragment.Header.MsgType), addr, fragment.Header)
			return conn, dtlserrors.WarnHandshakeMessageMustBeEncrypted
		}
	}
	return conn, nil
}
