package statemachine

import (
	"encoding/binary"
	"log"
	"math"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/record"
	"github.com/hrissan/tinydtls/transport/options"
)

func (conn *ConnectionImpl) receivedEncryptedAck(opts *options.TransportOptions, messageData []byte) error {
	insideBody, err := record.ParseAcks(messageData)
	if err != nil {
		return dtlserrors.ErrEncryptedAckMessageHeaderParsing
	}
	log.Printf("dtls: got ack record (encrypted) %d bytes from %v, message(hex): %x", len(messageData), conn.addr, messageData)
	conn.processAckBody(opts, insideBody)
	// if all messages from epoch 2 acked, then switch sending epoch
	if conn.hctx != nil && conn.hctx.sendQueue.Len() == 0 && conn.keys.Send.Symmetric.Epoch == 2 {
		conn.keys.Send.Symmetric.ComputeKeys(conn.keys.Send.ApplicationTrafficSecret[:])
		conn.keys.Send.Symmetric.Epoch = 3
		conn.keys.SendNextSegmentSequence = 0
		conn.hctx = nil // TODO - reuse into pool
		conn.Handler = &exampleHandler{toSend: "Hello from client\n"}
		conn.handlerHasMoreData = true
	}
	return nil // ack occupies full record
}

func (conn *ConnectionImpl) processAckBody(opts *options.TransportOptions, insideBody []byte) {
	for ; len(insideBody) >= record.AckElementSize; insideBody = insideBody[record.AckElementSize:] {
		epoch := binary.BigEndian.Uint64(insideBody)
		seq := binary.BigEndian.Uint64(insideBody[8:])
		if epoch > math.MaxUint16 {
			opts.Stats.Warning(conn.addr, dtlserrors.WarnAckEpochOverflow)
			continue // prevent overflow below
		}
		rn := record.NumberWith(uint16(epoch), seq)
		if conn.hctx != nil {
			conn.hctx.sendQueue.Ack(conn, rn)
		}
		conn.processKeyUpdateAck(rn)
		conn.processNewSessionTicketAck(rn)
	}
}

func (conn *ConnectionImpl) processNewSessionTicketAck(rn record.Number) {
	if conn.sendNewSessionTicketMessageSeq != 0 && conn.sendNewSessionTicketRN == (record.Number{}) || conn.sendNewSessionTicketRN != rn {
		return
	}
	log.Printf("NewSessionTicket ack received")
	conn.sendNewSessionTicketMessageSeq = 0
	conn.sendNewSessionTicketRN = record.Number{}
}

func (conn *ConnectionImpl) processKeyUpdateAck(rn record.Number) {
	if conn.sendKeyUpdateMessageSeq != 0 && conn.sendKeyUpdateRN == (record.Number{}) || conn.sendKeyUpdateRN != rn {
		return
	}
	log.Printf("KeyUpdate ack received")
	conn.sendKeyUpdateMessageSeq = 0
	conn.sendKeyUpdateRN = record.Number{}
	conn.sendKeyUpdateUpdateRequested = false // must not be necessary
	// now when we received ack for KeyUpdate, we must update our keys
	conn.keys.Send.ComputeNextApplicationTrafficSecret(conn.roleServer) // next application traffic secret is calculated from the previous one
	conn.keys.Send.Symmetric.ComputeKeys(conn.keys.Send.ApplicationTrafficSecret[:])
	conn.keys.Send.Symmetric.Epoch++
	conn.keys.SendNextSegmentSequence = 0
}
