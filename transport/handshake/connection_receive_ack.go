package handshake

import (
	"encoding/binary"
	"log"
	"math"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/options"
)

func (conn *ConnectionImpl) ProcessEncryptedAck(opts *options.TransportOptions, messageData []byte) error {
	insideBody, err := format.ParseRecordAcks(messageData)
	if err != nil {
		return dtlserrors.ErrEncryptedAckMessageHeaderParsing
	}
	log.Printf("dtls: got ack record (encrypted) %d bytes from %v, message(hex): %x", len(messageData), conn.Addr, messageData)
	conn.processAckBody(opts, insideBody)
	// if all messages from epoch 2 acked, then switch sending epoch
	if conn.Handshake != nil && conn.Handshake.SendQueue.Len() == 0 && conn.Keys.Send.Symmetric.Epoch == 2 {
		conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
		conn.Keys.Send.Symmetric.Epoch = 3
		conn.Keys.SendNextSegmentSequence = 0
		conn.Handshake = nil // TODO - reuse into pool
		conn.Handler = &exampleHandler{toSend: "Hello from client\n"}
		conn.HandlerHasMoreData = true
	}
	return nil // ack occupies full record
}

func (conn *ConnectionImpl) processAckBody(opts *options.TransportOptions, insideBody []byte) {
	for ; len(insideBody) >= format.AckRecordNumberSize; insideBody = insideBody[format.AckRecordNumberSize:] {
		epoch := binary.BigEndian.Uint64(insideBody)
		seq := binary.BigEndian.Uint64(insideBody[8:])
		if epoch > math.MaxUint16 {
			opts.Stats.Warning(conn.Addr, dtlserrors.WarnAckEpochOverflow)
			continue // prevent overflow below
		}
		rn := format.RecordNumberWith(uint16(epoch), seq)
		if conn.Handshake != nil {
			conn.Handshake.SendQueue.Ack(conn, rn)
		}
		conn.processKeyUpdateAck(rn)
		conn.processNewSessionTicketAck(rn)
	}
}

func (conn *ConnectionImpl) processNewSessionTicketAck(rn format.RecordNumber) {
	if conn.sendNewSessionTicketMessageSeq != 0 && conn.sendNewSessionTicketRN == (format.RecordNumber{}) || conn.sendNewSessionTicketRN != rn {
		return
	}
	log.Printf("NewSessionTicket ack received")
	conn.sendNewSessionTicketMessageSeq = 0
	conn.sendNewSessionTicketRN = format.RecordNumber{}
}

func (conn *ConnectionImpl) processKeyUpdateAck(rn format.RecordNumber) {
	if conn.sendKeyUpdateMessageSeq != 0 && conn.sendKeyUpdateRN == (format.RecordNumber{}) || conn.sendKeyUpdateRN != rn {
		return
	}
	log.Printf("KeyUpdate ack received")
	conn.sendKeyUpdateMessageSeq = 0
	conn.sendKeyUpdateRN = format.RecordNumber{}
	conn.sendKeyUpdateUpdateRequested = false // must not be necessary
	// now when we received ack for KeyUpdate, we must update our keys
	conn.Keys.Send.ComputeNextApplicationTrafficSecret(conn.RoleServer) // next application traffic secret is calculated from the previous one
	conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
	conn.Keys.Send.Symmetric.Epoch++
	conn.Keys.SendNextSegmentSequence = 0
}
