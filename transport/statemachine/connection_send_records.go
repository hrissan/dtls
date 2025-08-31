// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"math"
	"math/rand"

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
	userPadding := rand.Intn(4) // TODO - remove
	hdrSize, insideBody, ok := conn.prepareProtect(datagramLeft, opts.Use8BitSeq, userPadding)
	if !ok || len(insideBody) <= handshake.FragmentHeaderSize {
		return
	}
	msg.Header.FragmentLength = min(maxFragmentLength, safecast.Cast[uint32](len(insideBody)-handshake.FragmentHeaderSize)) // safe due to check above, but only if Msg.Body is limited
	if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
		return // do not send tiny records at the end of datagram
	}
	insideBody = msg.Header.Write(insideBody[:0])
	insideBody = append(insideBody, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)

	recordSize, rn, err = conn.protectRecord(record.RecordTypeHandshake,
		datagramLeft, userPadding, hdrSize, len(insideBody))
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

// datagramLeft is space to the end of datagram
// Reserves space for header and padding, returns ok and insideBody to write application data into,
// or (if even 0-byte application data will not fit), returns !ok.
// Caller should check if his data fits into insideBody, put it there.
func (conn *Connection) prepareProtect(datagramLeft []byte, use8BitSeq bool, userPadding int) (hdrSize int, insideBody []byte, ok bool) {
	sealSize, snBlockSize := conn.keys.Send.Symmetric.RecordOverhead()
	hdrSize = record.OutgoingCiphertextRecordHeader16
	if use8BitSeq {
		hdrSize = record.OutgoingCiphertextRecordHeader8
	}
	if len(datagramLeft)-hdrSize < snBlockSize { // not enough ciphertext to encrypt seq
		return 0, nil, false
	}
	cipherTextSize := 1 + userPadding + sealSize
	overhead := hdrSize + cipherTextSize
	userSpace := len(datagramLeft) - overhead
	if userSpace < 0 {
		return 0, nil, false
	}
	return hdrSize, datagramLeft[hdrSize : hdrSize+userSpace], true
}

func (conn *Connection) protectRecord(recordType byte, datagramLeft []byte, userPadding int, hdrSize int, insideSize int) (recordSize int, _ record.Number, _ error) {
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
	recordSize = conn.keys.Send.Symmetric.Protect(rn, encryptSN, recordType, datagramLeft, userPadding, hdrSize, insideSize)
	return recordSize, rn, nil
}

func encryptSequenceNumbers(seqNum []byte, mask [2]byte) {
	if len(seqNum) == 1 {
		seqNum[0] ^= mask[0]
		return
	}
	if len(seqNum) == 2 {
		seqNum[0] ^= mask[0]
		seqNum[1] ^= mask[1]
		return
	}
	panic("seqNum must have 1 or 2 bytes")
}
