// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"fmt"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

func (conn *Connection) receivedEncryptedAckLocked(opts *options.TransportOptions, recordData []byte, rn record.Number) error {
	parser, err := record.NewAckParser(recordData)
	if err != nil {
		return dtlserrors.ErrEncryptedAckMessageHeaderParsing
	}
	fmt.Printf("dtls: got ack record (encrypted) %d bytes from %v, message(hex): %x\n", len(recordData), conn.addr, recordData)
	var epochSeqOverflowCounter int
	for {
		beingAckedRn, ok := parser.PopFront(&epochSeqOverflowCounter)
		if !ok {
			break
		}
		// [rfc9147:7.1] During the handshake, ACK records MUST be sent with an epoch which is equal to or higher
		if rn.Epoch() < beingAckedRn.Epoch() && beingAckedRn.Epoch() < 3 { // ack record cannot ack future epochs
			continue
		}
		if conn.hctx != nil {
			conn.hctx.sendQueue.Ack(conn, beingAckedRn)
		}
		conn.processKeyUpdateAck(beingAckedRn)
		conn.processNewSessionTicketAck(beingAckedRn)
	}
	if epochSeqOverflowCounter != 0 {
		opts.Stats.Warning(conn.addr, dtlserrors.WarnAckEpochSeqnumOverflow)
	}
	// if all messages from epoch 2 acked, then switch sending epoch
	if conn.hctx != nil && conn.hctx.sendQueue.Len() == 0 && conn.keys.SendEpoch == 2 {
		conn.keys.Send.Symmetric = conn.keys.Suite().NewSymmetricKeys(conn.keys.Send.ApplicationTrafficSecret)
		conn.keys.SendEpoch = 3
		conn.keys.SendNextSegmentSequence = 0
		conn.hctx = nil                // TODO - reuse into pool
		conn.handler.OnConnectLocked() //  = &exampleHandler{toSend: "Hello from client\n"}
		conn.stateID = smIDPostHandshake
		conn.SignalWriteable()
	}
	return nil // ack occupies full record
}

func (conn *Connection) processNewSessionTicketAck(rn record.Number) {
	if conn.sendNewSessionTicketMessageSeq == 0 {
		return
	}
	if conn.sentNewSessionTicketRN == (record.Number{}) || conn.sentNewSessionTicketRN != rn {
		return
	}
	fmt.Printf("NewSessionTicket ack received\n")
	conn.sendNewSessionTicketMessageSeq = 0
	conn.sentNewSessionTicketRN = record.Number{}
}

func (conn *Connection) processKeyUpdateAck(rn record.Number) {
	if !conn.keyUpdateInProgress() {
		return
	}
	if conn.sentKeyUpdateRN == (record.Number{}) || conn.sentKeyUpdateRN != rn {
		return
	}
	fmt.Printf("KeyUpdate ack received\n")
	conn.sendKeyUpdateMessageSeq = 0
	conn.sentKeyUpdateRN = record.Number{}
	conn.sendKeyUpdateUpdateRequested = false // must not be necessary
	// now when we received ack for KeyUpdate, we must update our keys
	conn.keys.Send.ComputeNextApplicationTrafficSecret(conn.keys.Suite(), "send")
	conn.keys.Send.Symmetric = conn.keys.Suite().NewSymmetricKeys(conn.keys.Send.ApplicationTrafficSecret)
	conn.keys.SendEpoch++
	conn.keys.SendNextSegmentSequence = 0
}
