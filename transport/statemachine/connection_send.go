package statemachine

import (
	"log"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/record"
	"github.com/hrissan/tinydtls/replay"
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
	if conn.keys.SendAcks.GetBitCount() != 0 {
		return true
	}
	return conn.handlerHasMoreData ||
		(conn.sendKeyUpdateMessageSeq != 0 && (conn.sendKeyUpdateRN == record.Number{})) ||
		(conn.sendNewSessionTicketMessageSeq != 0 && (conn.sendNewSessionTicketRN == record.Number{}))
}

// must not write over len(datagram), returns part of datagram filled
func (conn *ConnectionImpl) ConstructDatagram(datagram []byte) (datagramSize int, addToSendQueue bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	var err error
	datagramSize, addToSendQueue, err = conn.constructDatagram(datagram)
	if err != nil {
		log.Printf("TODO - close connection")
	}
	return
}

func (conn *ConnectionImpl) constructDatagram(datagram []byte) (int, bool, error) {
	var datagramSize int
	hctx := conn.hctx
	if hctx != nil {
		// we decided to first send our messages, then acks.
		// because message has a chance to ack the whole flight
		if recordSize, err := hctx.sendQueue.ConstructDatagram(conn, datagram[datagramSize:]); err != nil {
			return 0, false, err
		} else {
			datagramSize += recordSize
		}
		//uncomment to separate datagram by record type
		//if datagramSize != 0 {
		//	return datagramSize, true, nil
		//}
	}
	if recordSize, err := conn.constructDatagramAcks(datagram[datagramSize:]); err != nil {
		return 0, false, err
	} else {
		datagramSize += recordSize
	}
	//uncomment to separate datagram by record type
	//if datagramSize != 0 {
	//	return datagramSize, true, nil
	//}
	if conn.sendKeyUpdateMessageSeq != 0 && (conn.sendKeyUpdateRN == record.Number{}) {
		msgBody := make([]byte, 0, 1) // must be stack-allocated
		msgKeyUpdate := handshake.MsgKeyUpdate{UpdateRequested: conn.sendKeyUpdateUpdateRequested}
		msgBody = msgKeyUpdate.Write(msgBody)
		lenBody := uint32(len(msgBody))
		msg := handshake.Message{
			MsgType: handshake.MsgTypeKeyUpdate,
			MsgSeq:  conn.sendKeyUpdateMessageSeq,
			Body:    msgBody,
		}
		recordSize, fragmentInfo, rn, err := conn.constructRecord(datagram[datagramSize:],
			msg, 0, lenBody, nil)
		if err != nil {
			return 0, false, err
		}
		if recordSize != 0 {
			if fragmentInfo.FragmentOffset != 0 || fragmentInfo.FragmentLength != lenBody {
				panic("outgoing KeyUpdate must not be fragmented")
			}
			datagramSize += recordSize
			conn.sendKeyUpdateRN = rn
		}
		//uncomment to separate datagram by record type
		//if datagramSize != 0 {
		//	return datagramSize, true, nil
		//}
	}
	if conn.sendNewSessionTicketMessageSeq != 0 && (conn.sendNewSessionTicketRN != record.Number{}) {
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
		userSpace := len(datagram) - datagramSize - 1 - record.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
		if userSpace >= constants.MinFragmentBodySize {
			recordData := datagram[datagramSize+record.OutgoingCiphertextRecordHeader : datagramSize+record.OutgoingCiphertextRecordHeader+userSpace]
			recordSize, send, add := conn.Handler.OnWriteApplicationRecord(recordData)
			if recordSize > len(recordData) {
				panic("ciphertext user handler overflows allowed record")
			}
			if send {
				da, err := conn.constructCiphertextApplication(datagram[datagramSize : datagramSize+record.OutgoingCiphertextRecordHeader+recordSize])
				if err != nil {
					return 0, false, err
				}
				if len(da) > len(datagram[datagramSize:]) {
					panic("ciphertext application record construction length invariant failed")
				}
				datagramSize += len(da)
			}
			if !add {
				conn.handlerHasMoreData = false
			}
		}
	}
	return datagramSize, conn.hasDataToSendLocked(), nil
}

func (conn *ConnectionImpl) constructDatagramAcks(datagram []byte) (int, error) {
	acks := &conn.keys.SendAcks
	acksSize := acks.GetBitCount()
	if acksSize == 0 {
		return 0, nil
	}
	acksSpace := len(datagram) - record.AckHeaderSize - record.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
	if acksSpace < record.AckElementSize { // not a single one fits
		return 0, nil
	}
	acksCount := min(acksSize, acksSpace/record.AckElementSize)
	if acksSpace < constants.MinFragmentBodySize && acksCount != acks.GetBitCount() {
		return 0, nil // do not send tiny records at the end of datagram
	}
	sendAcks := make([]record.Number, 0, replay.Width) // must be constant to allocate on stack
	nextReceiveSeq := acks.GetNextReceivedSeq()
	for i := uint64(0); i < replay.Width; i++ {
		if nextReceiveSeq+i < replay.Width { // anomaly around 0
			continue
		}
		seq := nextReceiveSeq + i - replay.Width
		if acks.IsSetBit(seq) {
			sendAcks = append(sendAcks, record.NumberWith(conn.keys.SendAcksEpoch, seq))
			//log.Printf("preparing to send ack={%d,%d}", conn.keys.SendAcksEpoch, seq)
			acks.ClearBit(seq)
		}
	}
	if len(sendAcks) > acksSize {
		panic("too many sendAcks")
	}
	da, err := conn.constructCiphertextAck(datagram[:0], sendAcks)
	if err != nil {
		return 0, err
	}
	if len(da) > len(datagram) {
		panic("ciphertext ack record construction length invariant failed")
	}
	return len(da), nil
}
