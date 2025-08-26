// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/replay"
	"github.com/hrissan/dtls/safecast"
	"github.com/hrissan/dtls/transport/options"
)

func (conn *Connection) SignalWriteable() {
	conn.snd.RegisterConnectionForSend(conn)
}

func (conn *Connection) hasDataToSend() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.hasDataToSendLocked()
}

func (conn *Connection) hasDataToSendLocked() bool {
	hctx := conn.hctx
	if hctx != nil && hctx.sendQueue.HasDataToSend() {
		return true
	}
	if conn.keys.Send.Symmetric.Epoch != 0 && conn.keys.SendAcks.GetBitCount() != 0 {
		return true
	}
	return (conn.keyUpdateInProgress() && (conn.sentKeyUpdateRN == record.Number{})) ||
		(conn.sendNewSessionTicketMessageSeq != 0 && (conn.sentNewSessionTicketRN == record.Number{}))
}

// must not write over len(datagram), returns part of datagram filled
func (conn *Connection) constructDatagram(opts *options.TransportOptions, datagram []byte) (addr netip.AddrPort, datagramSize int, addToSendQueue bool, closed bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	addr = conn.addr
	var err error
	datagramSize, addToSendQueue, err = conn.constructDatagramLocked(opts, datagram)
	if err != nil && conn.shutdownLockedShouldSignal(err) {
		fmt.Printf("seq overflow or another serious problem in connection to: %v\n", addr)
		addToSendQueue = true
	}
	if conn.stateID == smIDShutdown {
		conn.handler.OnDisconnectLocked(err)
		// TODO - append alert to datagram
		conn.stateID = smIDClosed
	}
	closed = conn.stateID == smIDClosed
	return
}

func (conn *Connection) constructDatagramLocked(opts *options.TransportOptions, datagram []byte) (int, bool, error) {
	// when user calls SignalWriteable, we do not want to take lock and set flag.
	// instead, connection is registered in sender, and later when constructDatagram
	// is called once, we must return true from it repeatedly (on non-error paths at least)
	// until we finally call to OnWriteRecordLocked, and it returns 'no more data'

	var datagramSize int
	hctx := conn.hctx
	// we send acks before messages, because peer with receive queue for the single message
	// can only receive subsequent message if their current one is fully acked

	if recordSize, err := conn.constructDatagramAcks(opts, datagram[datagramSize:]); err != nil {
		return 0, false, err
	} else {
		datagramSize += recordSize
	}
	//uncomment to separate datagram by record type
	//if datagramSize != 0 {
	//	return datagramSize, true, nil
	//}
	if hctx != nil {
		// we decided to first send our messages, then acks.
		// because message has a chance to ack the whole flight
		if recordSize, err := hctx.sendQueue.ConstructDatagram(conn, opts, datagram[datagramSize:]); err != nil {
			return 0, false, err
		} else {
			datagramSize += recordSize
		}
		//uncomment to separate datagram by record type
		//if datagramSize != 0 {
		//	return datagramSize, true, nil
		//}
	}
	if conn.keyUpdateInProgress() && (conn.sentKeyUpdateRN == record.Number{}) {
		msgBody := make([]byte, 0, 1) // must be stack-allocated
		msgKeyUpdate := handshake.MsgKeyUpdate{UpdateRequested: conn.sendKeyUpdateUpdateRequested}
		msgBody = msgKeyUpdate.Write(msgBody)
		lenBody := safecast.Cast[uint32](len(msgBody))
		msg := handshake.Message{
			MsgType: handshake.MsgTypeKeyUpdate,
			MsgSeq:  conn.sendKeyUpdateMessageSeq,
			Body:    msgBody,
		}
		recordSize, fragmentInfo, rn, err := conn.constructRecord(opts, datagram[datagramSize:],
			msg, 0, lenBody, nil)
		if err != nil {
			return 0, false, err
		}
		if recordSize != 0 {
			if fragmentInfo.FragmentOffset != 0 || fragmentInfo.FragmentLength != lenBody {
				panic("outgoing KeyUpdate must not be fragmented")
			}
			datagramSize += recordSize
			conn.sentKeyUpdateRN = rn
		}
		//uncomment to separate datagram by record type
		//if datagramSize != 0 {
		//	return datagramSize, true, nil
		//}
	}
	if conn.sendNewSessionTicketMessageSeq != 0 && (conn.sentNewSessionTicketRN != record.Number{}) {
		// TODO
	}
	if conn.stateID != smIDPostHandshake { // application data
		return datagramSize, conn.hasDataToSendLocked(), nil
	}
	// If we remove "if" below, we put ack for client finished together with
	// application data into the same datagram. Then wolfSSL_connect will return
	// err = -441, Application data is available for reading
	// TODO: investigate, contact WolfSSL team
	//if datagramSize > 0 {
	//	return datagramSize, true, nil
	//}
	hdrSize := record.OutgoingCiphertextRecordHeader16
	hdrSize, insideBody, ok := conn.prepareProtect(datagram[datagramSize:], opts.Use8BitSeq)
	if !ok || len(insideBody) < constants.MinFragmentBodySize {
		return datagramSize, true, nil
	}
	insideSize, send, wr, err := conn.handler.OnWriteRecordLocked(insideBody)
	if err != nil {
		return datagramSize, wr, err
	}
	if insideSize > len(insideBody) {
		panic("ciphertext user handler overflows allowed record")
	}
	if send {
		recordSize, _, err := conn.protectRecord(record.RecordTypeApplicationData, datagram[datagramSize:], hdrSize, insideSize)
		if err != nil {
			return 0, false, err
		}
		datagramSize += recordSize
	}
	return datagramSize, wr || conn.hasDataToSendLocked(), nil
}

func (conn *Connection) constructDatagramAcks(opts *options.TransportOptions, datagramLeft []byte) (int, error) {
	if conn.keys.Send.Symmetric.Epoch == 0 {
		return 0, nil // no one should believe unencrypted acks, so we never send them
	}
	acks := &conn.keys.SendAcks
	acksSize := acks.GetBitCount()
	if acksSize == 0 {
		return 0, nil
	}
	hdrSize := record.OutgoingCiphertextRecordHeader16
	hdrSize, insideBody, ok := conn.prepareProtect(datagramLeft, opts.Use8BitSeq)
	if !ok || len(insideBody) < record.AckHeaderSize+record.AckElementSize { // not a single one fits
		return 0, nil
	}

	acksCount := min(acksSize, (len(insideBody)-record.AckHeaderSize)/record.AckElementSize)
	if len(insideBody) < constants.MinFragmentBodySize && acksCount != acks.GetBitCount() {
		return 0, nil // do not send tiny records at the end of datagram
	}
	nextReceiveSeq := acks.GetNextReceivedSeq()
	binary.BigEndian.PutUint16(insideBody, safecast.Cast[uint16](acksCount*record.AckElementSize))
	offset := record.AckHeaderSize
	for i := uint64(0); i < replay.Width; i++ {
		if nextReceiveSeq+i < replay.Width { // anomaly around 0
			continue
		}
		seq := nextReceiveSeq + i - replay.Width
		if acks.IsSetBit(seq) {
			binary.BigEndian.PutUint64(insideBody[offset:], uint64(conn.keys.SendAcksEpoch)) // widening
			binary.BigEndian.PutUint64(insideBody[offset+8:], seq)
			offset += record.AckElementSize
			acks.ClearBit(seq)
		}
	}
	if offset != record.AckHeaderSize+acksCount*record.AckElementSize {
		panic("error calculating space for acks")
	}
	recordSize, _, err := conn.protectRecord(record.RecordTypeAck, datagramLeft, hdrSize, offset)
	if err != nil {
		return 0, err
	}
	return recordSize, nil
}
