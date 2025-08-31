// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"math"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/safecast"
	"github.com/hrissan/dtls/transport/options"
)

func (conn *Connection) constructRecord(opts *options.TransportOptions, datagramLeft []byte, handshakeMsg handshake.Message, fragmentOffset uint32, maxFragmentLength uint32, sendNextSegmentSequenceEpoch0 *uint16) (recordSize int, fragmentInfo handshake.FragmentInfo, rn record.Number, err error) {
	// during fragmenting we always write header at the start of the message, and then part of the body
	if fragmentOffset >= handshakeMsg.Len32() {
		// >=, because when fragment offset reaches end, message offset is advanced, and fragment offset resets to 0
		panic("invariant of send queue fragment offset violated")
	}
	msg := handshake.Fragment{
		Header: handshake.FragmentHeader{
			MsgType: handshakeMsg.MsgType,
			Length:  handshakeMsg.Len32(),
			FragmentInfo: handshake.FragmentInfo{
				MsgSeq:         handshakeMsg.MsgSeq,
				FragmentOffset: fragmentOffset,
				FragmentLength: 0,
			},
		},
		Body: handshakeMsg.Body,
	}
	if handshakeMsg.MsgType == handshake.MsgTypeClientHello || handshakeMsg.MsgType == handshake.MsgTypeServerHello {
		if sendNextSegmentSequenceEpoch0 == nil {
			panic("the same check for plaintext record should be above")
		}
		remainingSpace := len(datagramLeft) - handshake.FragmentHeaderSize + record.PlaintextRecordHeaderSize
		if remainingSpace <= 0 {
			return
		}
		msg.Header.FragmentLength = min(maxFragmentLength, safecast.Cast[uint32](remainingSpace))
		if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
			return // do not send tiny records at the end of datagram
		}
		da, rn, err := conn.constructPlaintextRecord(datagramLeft[:0], msg, sendNextSegmentSequenceEpoch0)
		if len(da) != int(msg.Header.FragmentLength+handshake.FragmentHeaderSize+record.PlaintextRecordHeaderSize) { // safe if Header.FragmentLength is in spec
			panic("plaintext handshake record construction length invariant failed")
		}
		if err != nil {
			return 0, handshake.FragmentInfo{}, record.Number{}, err
		}
		return len(da), msg.Header.FragmentInfo, rn, nil
	}
	hdrSize, insideBody, ok := conn.prepareProtect(datagramLeft, opts.Use8BitSeq)
	if !ok || len(insideBody) <= handshake.FragmentHeaderSize {
		return
	}
	msg.Header.FragmentLength = min(maxFragmentLength, safecast.Cast[uint32](len(insideBody)-handshake.FragmentHeaderSize)) // safe due to check above, but only if Msg.Body is limited
	if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
		return // do not send tiny records at the end of datagram
	}
	insideBody = msg.Header.Write(insideBody[:0])
	insideBody = append(insideBody, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)

	recordSize, rn, err = conn.protectRecord(record.RecordTypeHandshake, datagramLeft, hdrSize, len(insideBody))
	if err != nil {
		return 0, handshake.FragmentInfo{}, record.Number{}, err
	}
	return recordSize, msg.Header.FragmentInfo, rn, nil
}

func (conn *Connection) constructPlaintextRecord(datagramLeft []byte, msg handshake.Fragment, sendNextSegmentSequenceEpoch0 *uint16) ([]byte, record.Number, error) {
	if *sendNextSegmentSequenceEpoch0 == math.MaxUint16 { // linter does not like >= here
		// We arbitrarily decided that we do not need more outgoing sequence numbers for epoch 0
		// We needed code to prevent overflow below anyway
		return nil, record.Number{}, dtlserrors.ErrSendEpoch0RecordSeqOverflow
	}
	rn := record.NumberWith(0, uint64(*sendNextSegmentSequenceEpoch0)) // widening
	recordHdr := record.PlaintextHeader{
		ContentType:    record.RecordTypeHandshake,
		SequenceNumber: uint64(*sendNextSegmentSequenceEpoch0), // widening
	}
	*sendNextSegmentSequenceEpoch0++ // never overflows due to check above
	datagramLeft = recordHdr.Write(datagramLeft, safecast.Cast[uint16](handshake.FragmentHeaderSize+msg.Header.FragmentLength))
	datagramLeft = msg.Header.Write(datagramLeft)
	datagramLeft = append(datagramLeft, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	return datagramLeft, rn, nil
}

// returns seq number to use
func (conn *Connection) checkSendLimit() (uint64, error) {
	sendLimit := min(conn.keys.SequenceNumberLimit(), constants.MaxProtectionLimitSend)
	if conn.keys.SendNextSegmentSequence >= sendLimit {
		return 0, dtlserrors.ErrSendRecordSeqOverflow
	}
	seq := conn.keys.SendNextSegmentSequence                                          // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.keys.SendNextSegmentSequence++                                               // does not overflow due to checkSendLimit() above
	if conn.keys.SendEpoch < 3 || conn.keys.SendNextSegmentSequence < sendLimit*3/4 { // simple heuristic
		return seq, nil
	}
	return seq, conn.keyUpdateStart(false)
}

// Writes header and returns body to write used data to.
// can return empty body, useful if the caller wants to write empty application data.
// Pass datagramLeft, hdrSize and how many bytes pf insideBody filled to protectRecord
func (conn *Connection) prepareProtect(datagramLeft []byte, use8BitSeq bool) (hdrSize int, insideBody []byte, ok bool) {
	return conn.keys.Send.Symmetric.PrepareProtect(datagramLeft, use8BitSeq)
}

func (conn *Connection) protectRecord(recordType byte, datagramLeft []byte, hdrSize int, insideSize int) (recordSize int, _ record.Number, _ error) {
	if hdrSize != record.OutgoingCiphertextRecordHeader8 && hdrSize != record.OutgoingCiphertextRecordHeader16 {
		panic("outgoing record header size must be 4 or 5 bytes")
	}
	if insideSize > record.MaxPlaintextRecordLength {
		panic("outgoing record size too big")
	}
	seq, err := conn.checkSendLimit()
	if err != nil {
		return 0, record.Number{}, err
	}
	rn := record.NumberWith(conn.keys.SendEpoch, seq)
	encryptSN := !conn.keys.DoNotEncryptSequenceNumbers
	recordSize = conn.keys.Send.Symmetric.Protect(rn, encryptSN, recordType, datagramLeft, hdrSize, insideSize)
	return recordSize, rn, nil
}
