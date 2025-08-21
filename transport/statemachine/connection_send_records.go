// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"encoding/binary"
	"log"
	"math"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
	"github.com/hrissan/dtls/record"
)

func (conn *ConnectionImpl) constructRecord(datagramLeft []byte, handshakeMsg handshake.Message, fragmentOffset uint32, maxFragmentLength uint32, sendNextSegmentSequenceEpoch0 *uint16) (recordSize int, fragmentInfo handshake.FragmentInfo, rn record.Number, err error) {
	// during fragmenting we always write header at the start of the message, and then part of the body
	if fragmentOffset >= uint32(len(handshakeMsg.Body)) { // >=, because when fragment offset reaches end, message offset is advanced, and fragment offset resets to 0
		panic("invariant of send queue fragment offset violated")
	}
	msg := handshake.Fragment{
		Header: handshake.FragmentHeader{
			MsgType: handshakeMsg.MsgType,
			Length:  uint32(len(handshakeMsg.Body)),
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
		msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
		if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
			return // do not send tiny records at the end of datagram
		}
		da, rn, err := conn.constructPlaintextRecord(datagramLeft[:0], msg, sendNextSegmentSequenceEpoch0)
		if uint32(len(da)) != msg.Header.FragmentLength+handshake.FragmentHeaderSize+record.PlaintextRecordHeaderSize {
			panic("plaintext handshake record construction length invariant failed")
		}
		if err != nil {
			return 0, handshake.FragmentInfo{}, record.Number{}, err
		}
		return len(da), msg.Header.FragmentInfo, rn, nil
	}
	hdrSize := record.OutgoingCiphertextRecordHeader16
	insideBody, ok := conn.prepareProtect(datagramLeft, hdrSize)
	if !ok || len(insideBody) <= handshake.FragmentHeaderSize {
		return
	}
	msg.Header.FragmentLength = min(maxFragmentLength, uint32(len(insideBody)-handshake.FragmentHeaderSize))
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

func (conn *ConnectionImpl) constructPlaintextRecord(data []byte, msg handshake.Fragment, sendNextSegmentSequenceEpoch0 *uint16) ([]byte, record.Number, error) {
	if *sendNextSegmentSequenceEpoch0 >= math.MaxUint16 {
		// We arbitrarily decided that we do not need more outgoing sequence numbers for epoch 0
		// We needed code to prevent overflow below anyway
		return nil, record.Number{}, dtlserrors.ErrSendEpoch0RecordSeqOverflow
	}
	rn := record.NumberWith(0, uint64(*sendNextSegmentSequenceEpoch0))
	recordHdr := record.PlaintextHeader{
		ContentType:    record.RecordTypeHandshake,
		SequenceNumber: uint64(*sendNextSegmentSequenceEpoch0),
	}
	*sendNextSegmentSequenceEpoch0++ // never overflows due to check above
	data = recordHdr.Write(data, handshake.FragmentHeaderSize+int(msg.Header.FragmentLength))
	data = msg.Header.Write(data)
	data = append(data, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	return data, rn, nil
}

// returns seq number to use
func (conn *ConnectionImpl) checkSendLimit() (uint64, error) {
	sendLimit := conn.keys.SequenceNumberLimit()
	if conn.keys.SendNextSegmentSequence >= sendLimit {
		return 0, dtlserrors.ErrSendRecordSeqOverflow
	}
	seq := conn.keys.SendNextSegmentSequence                                                     // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.keys.SendNextSegmentSequence++                                                          // does not overflow due to checkSendLimit() above
	if conn.keys.Send.Symmetric.Epoch < 3 || conn.keys.SendNextSegmentSequence < sendLimit*3/4 { // simple heuristic
		return seq, nil
	}
	return seq, conn.startKeyUpdate(false)
}

// Writes header and returns body to write used data to.
// can return empty body, useful if the caller wants to write empty application data.
// Pass datagramLeft, hdrSize and how many bytes pf insideBody filled to protectRecord
func (conn *ConnectionImpl) prepareProtect(datagramLeft []byte, hdrSize int) (insideBody []byte, ok bool) {
	overhead := hdrSize + 1 + record.MaxOutgoingCiphertextRecordPadding + constants.AEADSealSize
	userSpace := len(datagramLeft) - overhead
	if userSpace < 0 {
		return nil, false
	}
	return datagramLeft[hdrSize : hdrSize+userSpace], true
}

func (conn *ConnectionImpl) protectRecord(recordType byte, datagramLeft []byte, hdrSize int, insideSize int) (recordSize int, _ record.Number, _ error) {
	if hdrSize != record.OutgoingCiphertextRecordHeader8 && hdrSize != record.OutgoingCiphertextRecordHeader16 {
		panic("outgoing record size must be 4 or 5 bytes")
	}
	seq, err := conn.checkSendLimit()
	if err != nil {
		return 0, record.Number{}, err
	}
	send := &conn.keys.Send
	epoch := send.Symmetric.Epoch
	rn := record.NumberWith(epoch, seq)
	log.Printf("constructing ciphertext application with rn={%d,%d} hdrSize = %d", rn.Epoch(), rn.SeqNum(), hdrSize)

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed.
	// Saving 1 byte for the sequence number seems very niche.
	// Saving on not including length of the last datagram is also very hard.
	// At the point we know it is the last one, we cannot not change header,
	// because it is "additional data" for AEAD
	firstByte := record.CiphertextHeaderFirstByte(false, hdrSize == record.OutgoingCiphertextRecordHeader16, true, epoch)
	// panic below would mean, caller violated invariant of using datagram space
	datagramLeft[0] = firstByte
	datagramLeft[hdrSize+insideSize] = recordType
	insideSize++

	padding := (insideSize + 1) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding; i++ {
		datagramLeft[hdrSize+insideSize] = 0
		insideSize++
	}

	var seqNumData []byte
	if hdrSize == record.OutgoingCiphertextRecordHeader8 {
		seqNumData = datagramLeft[1:2]
		seqNumData[0] = byte(seq)
		binary.BigEndian.PutUint16(datagramLeft[2:], uint16(insideSize+constants.AEADSealSize))
	} else {
		seqNumData = datagramLeft[1:3]
		binary.BigEndian.PutUint16(seqNumData, uint16(seq))
		binary.BigEndian.PutUint16(datagramLeft[3:], uint16(insideSize+constants.AEADSealSize))
	}

	encrypted := gcm.Seal(datagramLeft[hdrSize:hdrSize], iv[:], datagramLeft[hdrSize:hdrSize+insideSize], datagramLeft[:hdrSize])
	if &encrypted[0] != &datagramLeft[hdrSize] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(datagramLeft[hdrSize:hdrSize+insideSize+constants.AEADSealSize]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(seqNumData, datagramLeft[hdrSize:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return hdrSize + insideSize + constants.AEADSealSize, rn, nil
}
