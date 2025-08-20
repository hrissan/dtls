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

func (conn *ConnectionImpl) checkSendLimit() error {
	sendLimit := conn.keys.SequenceNumberLimit()
	if conn.keys.SendNextSegmentSequence >= sendLimit {
		return dtlserrors.ErrSendRecordSeqOverflow
	}
	if conn.keys.Send.Symmetric.Epoch < 3 || conn.keys.SendNextSegmentSequence < sendLimit*3/4 { // simple heuristic
		return nil
	}
	return conn.startKeyUpdate(false)
}

func (conn *ConnectionImpl) constructCiphertextRecord(recordData []byte, msg handshake.Fragment) ([]byte, record.Number, error) {
	if err := conn.checkSendLimit(); err != nil {
		return nil, record.Number{}, err
	}
	send := &conn.keys.Send
	epoch := send.Symmetric.Epoch
	rn := record.NumberWith(epoch, conn.keys.SendNextSegmentSequence)
	seq := conn.keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext handshake with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
	firstByte := record.CiphertextHeaderFirstByte(false, true, true, epoch)
	startRecordOffset := len(recordData)
	recordData = append(recordData, firstByte)
	recordData = binary.BigEndian.AppendUint16(recordData, uint16(seq))
	recordData = append(recordData, 0, 0) // fill length later
	startBodyOFfset := len(recordData)
	recordData = msg.Header.Write(recordData)
	recordData = append(recordData, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	recordData = append(recordData, record.RecordTypeHandshake)

	padding := len(recordData) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		recordData = append(recordData, 0)
	}

	binary.BigEndian.PutUint16(recordData[startRecordOffset+3:], uint16(len(recordData)-startBodyOFfset))

	encrypted := gcm.Seal(recordData[startBodyOFfset:startBodyOFfset], iv[:], recordData[startBodyOFfset:len(recordData)-constants.AEADSealSize], recordData[startRecordOffset:startBodyOFfset])
	if &encrypted[0] != &recordData[startBodyOFfset] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(recordData[startBodyOFfset:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(recordData[startRecordOffset+1:startRecordOffset+3], recordData[startBodyOFfset:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return recordData, rn, nil
}

func (conn *ConnectionImpl) constructCiphertextAck(recordBody []byte, acks []record.Number) ([]byte, error) {
	// TODO - harmonize with code above
	if err := conn.checkSendLimit(); err != nil {
		return nil, err
	}
	send := &conn.keys.Send
	epoch := send.Symmetric.Epoch
	rn := record.NumberWith(epoch, conn.keys.SendNextSegmentSequence)
	seq := conn.keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext ack with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
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

func (conn *ConnectionImpl) constructCiphertextApplication(recordBody []byte) ([]byte, error) {
	// TODO - harmonize with code above
	if err := conn.checkSendLimit(); err != nil {
		return nil, err
	}
	send := &conn.keys.Send
	epoch := send.Symmetric.Epoch
	rn := record.NumberWith(epoch, conn.keys.SendNextSegmentSequence)
	seq := conn.keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext application with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
	firstByte := record.CiphertextHeaderFirstByte(false, true, true, epoch)
	const hdrSize = record.OutgoingCiphertextRecordHeader
	recordBody = append(recordBody, record.RecordApplicationData)

	padding := len(recordBody) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		recordBody = append(recordBody, 0)
	}

	recordBody[0] = firstByte
	binary.BigEndian.PutUint16(recordBody[1:], uint16(seq))
	binary.BigEndian.PutUint16(recordBody[3:], uint16(len(recordBody)-hdrSize))

	encrypted := gcm.Seal(recordBody[hdrSize:hdrSize], iv[:], recordBody[hdrSize:len(recordBody)-constants.AEADSealSize], recordBody[:hdrSize])
	if &encrypted[0] != &recordBody[hdrSize] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(recordBody[hdrSize:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(recordBody[1:3], recordBody[hdrSize:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return recordBody, nil
}
