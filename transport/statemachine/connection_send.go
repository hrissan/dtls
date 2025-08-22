// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"encoding/binary"
	"log"
	"net/netip"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/replay"
	"github.com/hrissan/dtls/transport/options"
)

func (conn *ConnectionImpl) HasDataToSend() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.hasDataToSendLocked()
}

func (conn *ConnectionImpl) hasDataToSendLocked() bool {
	hctx := conn.hctx
	if hctx != nil && hctx.sendQueue.HasDataToSend() {
		return true
	}
	if conn.keys.Send.Symmetric.Epoch != 0 && conn.keys.SendAcks.GetBitCount() != 0 {
		return true
	}
	return conn.handlerHasMoreData ||
		(conn.keyUpdateInProgress() && (conn.sentKeyUpdateRN == record.Number{})) ||
		(conn.sendNewSessionTicketMessageSeq != 0 && (conn.sentNewSessionTicketRN == record.Number{}))
}

// must not write over len(datagram), returns part of datagram filled
func (conn *ConnectionImpl) ConstructDatagram(opts *options.TransportOptions, datagram []byte) (addr netip.AddrPort, datagramSize int, addToSendQueue bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	addr = conn.addr
	var err error
	datagramSize, addToSendQueue, err = conn.constructDatagram(opts, datagram)
	if err != nil {
		log.Printf("TODO - close connection")
	}
	return
}

func (conn *ConnectionImpl) constructDatagram(opts *options.TransportOptions, datagram []byte) (int, bool, error) {
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
		lenBody := uint32(len(msgBody))
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
	if conn.Handler != nil { // application data
		// If we remove "if" below, we put ack for client finished together with
		// application data into the same datagram. Then wolfSSL_connect will return
		// err = -441, Application data is available for reading
		// TODO: contact WolfSSL team
		if datagramSize > 0 {
			return datagramSize, true, nil
		}
		hdrSize := record.OutgoingCiphertextRecordHeader16
		hdrSize, insideBody, ok := conn.prepareProtect(datagram[datagramSize:], opts.Use8BitSeq)
		if ok && len(insideBody) >= constants.MinFragmentBodySize {
			insideSize, send, add := conn.Handler.OnWriteApplicationRecord(insideBody)
			if insideSize > len(insideBody) {
				panic("ciphertext user handler overflows allowed record")
			}
			if send {
				recordSize, _, err := conn.protectRecord(record.RecordTypeApplicationData, datagram[datagramSize:], hdrSize, insideSize)
				if err != nil {
					return 0, false, err
				}
				//if len(da) > len(datagram[datagramSize:]) {
				//	panic("ciphertext application record construction length invariant failed")
				//}
				datagramSize += recordSize
			}
			if !add {
				conn.handlerHasMoreData = false
			}
		}
	}
	return datagramSize, conn.hasDataToSendLocked(), nil
}

func (conn *ConnectionImpl) constructDatagramAcks(opts *options.TransportOptions, datagramLeft []byte) (int, error) {
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
	binary.BigEndian.PutUint16(insideBody, uint16(acksCount*record.AckElementSize))
	offset := record.AckHeaderSize
	for i := uint64(0); i < replay.Width; i++ {
		if nextReceiveSeq+i < replay.Width { // anomaly around 0
			continue
		}
		seq := nextReceiveSeq + i - replay.Width
		if acks.IsSetBit(seq) {
			binary.BigEndian.PutUint64(insideBody[offset:], uint64(conn.keys.SendAcksEpoch))
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
