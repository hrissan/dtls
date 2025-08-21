// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"encoding/binary"
	"log"
	"math"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/format"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
	"github.com/hrissan/dtls/record"
)

func (conn *ConnectionImpl) constructRecord(datagram []byte, handshakeMsg handshake.Message, fragmentOffset uint32, maxFragmentLength uint32, sendNextSegmentSequenceEpoch0 *uint16) (recordSize int, fragmentInfo handshake.FragmentInfo, rn record.Number, err error) {
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
		remainingSpace := len(datagram) - handshake.FragmentHeaderSize + record.PlaintextRecordHeaderSize
		if remainingSpace <= 0 {
			return
		}
		msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
		if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
			return // do not send tiny records at the end of datagram
		}
		da, rn, err := conn.constructPlaintextRecord(datagram[:0], msg, sendNextSegmentSequenceEpoch0)
		if uint32(len(da)) != msg.Header.FragmentLength+handshake.FragmentHeaderSize+record.PlaintextRecordHeaderSize {
			panic("plaintext handshake record construction length invariant failed")
		}
		if err != nil {
			return 0, handshake.FragmentInfo{}, record.Number{}, err
		}
		return len(da), msg.Header.FragmentInfo, rn, nil
	}
	remainingSpace := len(datagram) - handshake.FragmentHeaderSize - record.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
	if remainingSpace <= 0 {
		return
	}
	msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
	if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
		return // do not send tiny records at the end of datagram
	}
	da, rn, err := conn.constructCiphertextRecord(datagram[:0], msg)
	if err != nil {
		return 0, handshake.FragmentInfo{}, record.Number{}, err
	}
	if len(da) > len(datagram) {
		panic("ciphertext handshake record construction length invariant failed")
	}
	return len(da), msg.Header.FragmentInfo, rn, nil
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

func (conn *ConnectionImpl) constructCiphertextRecord(recordBody []byte, msg handshake.Fragment) ([]byte, record.Number, error) {
	if len(recordBody) != 0 {
		panic("must pass empty allocated slice with enough length")
	}
	seq, err := conn.checkSendLimit()
	if err != nil {
		return nil, record.Number{}, err
	}
	send := &conn.keys.Send
	epoch := send.Symmetric.Epoch
	rn := record.NumberWith(epoch, seq)
	log.Printf("constructing ciphertext handshake with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed.
	// Saving 1 byte for the sequence number seems very niche.
	// Saving on not including length of the last datagram is also very hard.
	// At the point we know it is the last one, we cannot not change header,
	// because it is "additional data" for AEAD
	firstByte := record.CiphertextHeaderFirstByte(false, true, true, epoch)
	startRecordOffset := len(recordBody)
	recordBody = append(recordBody, firstByte)
	recordBody = binary.BigEndian.AppendUint16(recordBody, uint16(seq))
	recordBody = append(recordBody, 0, 0) // fill length later
	startBodyOFfset := len(recordBody)
	recordBody = msg.Header.Write(recordBody)
	recordBody = append(recordBody, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	recordBody = append(recordBody, record.RecordTypeHandshake)

	padding := len(recordBody) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		recordBody = append(recordBody, 0)
	}

	binary.BigEndian.PutUint16(recordBody[startRecordOffset+3:], uint16(len(recordBody)-startBodyOFfset))

	encrypted := gcm.Seal(recordBody[startBodyOFfset:startBodyOFfset], iv[:], recordBody[startBodyOFfset:len(recordBody)-constants.AEADSealSize], recordBody[startRecordOffset:startBodyOFfset])
	if &encrypted[0] != &recordBody[startBodyOFfset] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(recordBody[startBodyOFfset:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(recordBody[startRecordOffset+1:startRecordOffset+3], recordBody[startBodyOFfset:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return recordBody, rn, nil
}

func (conn *ConnectionImpl) constructCiphertextAck(recordBody []byte, acks []record.Number) ([]byte, error) {
	if len(recordBody) != 0 {
		panic("must pass empty allocated slice with enough length")
	}
	seq, err := conn.checkSendLimit()
	if err != nil {
		return nil, err
	}
	send := &conn.keys.Send
	epoch := send.Symmetric.Epoch
	rn := record.NumberWith(epoch, seq)
	log.Printf("constructing ciphertext ack with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed.
	// Saving 1 byte for the sequence number seems very niche.
	// Saving on not including length of the last datagram is also very hard.
	// At the point we know it is the last one, we cannot not change header,
	// because it is "additional data" for AEAD
	firstByte := record.CiphertextHeaderFirstByte(false, true, true, epoch)
	recordBody = append(recordBody, firstByte)
	recordBody = binary.BigEndian.AppendUint16(recordBody, uint16(seq))
	recordBody = append(recordBody, 0, 0) // fill length later
	startBodyOFfset := len(recordBody)
	// serialization of ack message, TODO - move out?
	recordBody, mark := format.MarkUint16Offset(recordBody)
	for _, ack := range acks {
		recordBody = binary.BigEndian.AppendUint64(recordBody, uint64(ack.Epoch()))
		recordBody = binary.BigEndian.AppendUint64(recordBody, ack.SeqNum())
	}
	format.FillUint16Offset(recordBody, mark)
	recordBody = append(recordBody, record.RecordTypeAck)

	padding := len(recordBody) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		recordBody = append(recordBody, 0)
	}

	binary.BigEndian.PutUint16(recordBody[3:], uint16(len(recordBody)-startBodyOFfset))

	encrypted := gcm.Seal(recordBody[startBodyOFfset:startBodyOFfset], iv[:], recordBody[startBodyOFfset:len(recordBody)-constants.AEADSealSize], recordBody[:startBodyOFfset])
	if &encrypted[0] != &recordBody[startBodyOFfset] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(recordBody[startBodyOFfset:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(recordBody[1:3], recordBody[startBodyOFfset:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return recordBody, nil
}

func (conn *ConnectionImpl) constructCiphertextApplication(recordType byte, hdrSize int, recordBody []byte) ([]byte, error) {
	if hdrSize != record.OutgoingCiphertextRecordHeader8 && hdrSize != record.OutgoingCiphertextRecordHeader16 {
		panic("outgoing record size must be 4 or 5 bytes")
	}
	seq, err := conn.checkSendLimit()
	if err != nil {
		return nil, err
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
	recordBody = append(recordBody, recordType)

	padding := len(recordBody) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		recordBody = append(recordBody, 0)
	}

	recordBody[0] = firstByte
	var seqNumData []byte
	if hdrSize == record.OutgoingCiphertextRecordHeader8 {
		seqNumData = recordBody[1:2]
		recordBody[1] = byte(seq)
		binary.BigEndian.PutUint16(recordBody[2:], uint16(len(recordBody)-hdrSize))
	} else {
		seqNumData = recordBody[1:3]
		binary.BigEndian.PutUint16(recordBody[1:], uint16(seq))
		binary.BigEndian.PutUint16(recordBody[3:], uint16(len(recordBody)-hdrSize))
	}

	encrypted := gcm.Seal(recordBody[hdrSize:hdrSize], iv[:], recordBody[hdrSize:len(recordBody)-constants.AEADSealSize], recordBody[:hdrSize])
	if &encrypted[0] != &recordBody[hdrSize] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(recordBody[hdrSize:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(seqNumData, recordBody[hdrSize:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return recordBody, nil
}
