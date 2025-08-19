package statemachine

import (
	"encoding/binary"
	"log"
	"math"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/keys"
)

func (conn *ConnectionImpl) constructRecord(datagram []byte, handshakeMsg HandshakeMsg, fragmentOffset uint32, maxFragmentLength uint32, sendNextSegmentSequenceEpoch0 *uint16) (recordSize int, fragmentInfo handshake.FragmentInfo, rn format.RecordNumber, err error) {
	// during fragmenting we always write header at the start of the message, and then part of the body
	if fragmentOffset >= uint32(len(handshakeMsg.Body)) { // >=, because when fragment offset reaches end, message offset is advanced, and fragment offset resets to 0
		panic("invariant of send queue fragment offset violated")
	}
	msg := handshake.MessageHandshakeFragment{
		Header: handshake.MsgFragmentHeader{
			HandshakeType: handshakeMsg.HandshakeType,
			Length:        uint32(len(handshakeMsg.Body)),
			FragmentInfo: handshake.FragmentInfo{
				MsgSeq:         handshakeMsg.MessageSeq,
				FragmentOffset: fragmentOffset,
				FragmentLength: 0,
			},
		},
		Body: handshakeMsg.Body,
	}
	if handshakeMsg.HandshakeType == handshake.HandshakeTypeClientHello || handshakeMsg.HandshakeType == handshake.HandshakeTypeServerHello {
		if sendNextSegmentSequenceEpoch0 == nil {
			panic("the same check for plaintext record should be above")
		}
		remainingSpace := len(datagram) - handshake.MessageHandshakeHeaderSize + format.PlaintextRecordHeaderSize
		if remainingSpace <= 0 {
			return
		}
		msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
		if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
			return // do not send tiny records at the end of datagram
		}
		da, rn, err := conn.constructPlaintextRecord(datagram[:0], msg, sendNextSegmentSequenceEpoch0)
		if uint32(len(da)) != msg.Header.FragmentLength+handshake.MessageHandshakeHeaderSize+format.PlaintextRecordHeaderSize {
			panic("plaintext handshake record construction length invariant failed")
		}
		if err != nil {
			return 0, handshake.FragmentInfo{}, format.RecordNumber{}, err
		}
		return len(da), msg.Header.FragmentInfo, rn, nil
	}
	remainingSpace := len(datagram) - handshake.MessageHandshakeHeaderSize - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
	if remainingSpace <= 0 {
		return
	}
	msg.Header.FragmentLength = min(maxFragmentLength, uint32(remainingSpace))
	if msg.Header.FragmentLength <= constants.MinFragmentBodySize && msg.Header.FragmentLength != maxFragmentLength {
		return // do not send tiny records at the end of datagram
	}
	da, rn, err := conn.constructCiphertextRecord(datagram[:0], msg)
	if err != nil {
		return 0, handshake.FragmentInfo{}, format.RecordNumber{}, err
	}
	if len(da) > len(datagram) {
		panic("ciphertext handshake record construction length invariant failed")
	}
	return len(da), msg.Header.FragmentInfo, rn, nil
}

func (conn *ConnectionImpl) constructPlaintextRecord(data []byte, msg handshake.MessageHandshakeFragment, sendNextSegmentSequenceEpoch0 *uint16) ([]byte, format.RecordNumber, error) {
	if *sendNextSegmentSequenceEpoch0 >= math.MaxUint16 {
		// We arbitrarily decided that we do not need more outgoing sequence numbers for epoch 0
		// We needed code to prevent overflow below anyway
		return nil, format.RecordNumber{}, dtlserrors.ErrSendEpoch0RecordSeqOverflow
	}
	rn := format.RecordNumberWith(0, uint64(*sendNextSegmentSequenceEpoch0))
	recordHdr := format.PlaintextRecordHeader{
		ContentType:    format.PlaintextContentTypeHandshake,
		SequenceNumber: uint64(*sendNextSegmentSequenceEpoch0),
	}
	*sendNextSegmentSequenceEpoch0++ // never overflows due to check above
	data = recordHdr.Write(data, handshake.MessageHandshakeHeaderSize+int(msg.Header.FragmentLength))
	data = msg.Header.Write(data)
	data = append(data, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	return data, rn, nil
}

func (conn *ConnectionImpl) checkSendLimit() error {
	sendLimit := conn.Keys.SequenceNumberLimit()
	if conn.Keys.SendNextSegmentSequence >= sendLimit {
		return dtlserrors.ErrSendRecordSeqOverflow
	}
	if conn.Keys.Send.Symmetric.Epoch < 3 || conn.Keys.SendNextSegmentSequence < sendLimit*3/4 { // simple heuristic
		return nil
	}
	return conn.startKeyUpdate(false)
}

func (conn *ConnectionImpl) constructCiphertextRecord(datagram []byte, msg handshake.MessageHandshakeFragment) ([]byte, format.RecordNumber, error) {
	if err := conn.checkSendLimit(); err != nil {
		return nil, format.RecordNumber{}, err
	}
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.SendNextSegmentSequence)
	seq := conn.Keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.Keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext handshake with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
	hdr := format.NewCiphertextRecordHeader(false, true, true, epoch)
	startRecordOffset := len(datagram)
	datagram = append(datagram, hdr.FirstByte)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(seq))
	datagram = append(datagram, 0, 0) // fill length later
	startBodyOFfset := len(datagram)
	datagram = msg.Header.Write(datagram)
	datagram = append(datagram, msg.Body[msg.Header.FragmentOffset:msg.Header.FragmentOffset+msg.Header.FragmentLength]...)
	datagram = append(datagram, format.PlaintextContentTypeHandshake)

	padding := len(datagram) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		datagram = append(datagram, 0)
	}

	binary.BigEndian.PutUint16(datagram[startRecordOffset+3:], uint16(len(datagram)-startBodyOFfset))

	encrypted := gcm.Seal(datagram[startBodyOFfset:startBodyOFfset], iv[:], datagram[startBodyOFfset:len(datagram)-constants.AEADSealSize], datagram[startRecordOffset:startBodyOFfset])
	if &encrypted[0] != &datagram[startBodyOFfset] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(datagram[startBodyOFfset:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.Keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(datagram[startRecordOffset+1:startRecordOffset+3], datagram[startBodyOFfset:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return datagram, rn, nil
}

func (conn *ConnectionImpl) constructCiphertextAck(datagram []byte, acks []format.RecordNumber) ([]byte, error) {
	// TODO - harmonize with code above
	if err := conn.checkSendLimit(); err != nil {
		return nil, err
	}
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.SendNextSegmentSequence)
	seq := conn.Keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.Keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext ack with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
	hdr := format.NewCiphertextRecordHeader(false, true, true, epoch)
	datagram = append(datagram, hdr.FirstByte)
	datagram = binary.BigEndian.AppendUint16(datagram, uint16(seq))
	datagram = append(datagram, 0, 0) // fill length later
	startBodyOFfset := len(datagram)
	// serialization of ack message, TODO - move out?
	datagram, mark := format.MarkUint16Offset(datagram)
	for _, ack := range acks {
		datagram = binary.BigEndian.AppendUint64(datagram, uint64(ack.Epoch()))
		datagram = binary.BigEndian.AppendUint64(datagram, ack.SeqNum())
	}
	format.FillUint16Offset(datagram, mark)
	datagram = append(datagram, format.PlaintextContentTypeAck)

	padding := len(datagram) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		datagram = append(datagram, 0)
	}

	binary.BigEndian.PutUint16(datagram[3:], uint16(len(datagram)-startBodyOFfset))

	encrypted := gcm.Seal(datagram[startBodyOFfset:startBodyOFfset], iv[:], datagram[startBodyOFfset:len(datagram)-constants.AEADSealSize], datagram[:startBodyOFfset])
	if &encrypted[0] != &datagram[startBodyOFfset] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(datagram[startBodyOFfset:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.Keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(datagram[1:3], datagram[startBodyOFfset:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return datagram, nil
}

func (conn *ConnectionImpl) constructCiphertextApplication(record []byte) ([]byte, error) {
	// TODO - harmonize with code above
	if err := conn.checkSendLimit(); err != nil {
		return nil, err
	}
	send := &conn.Keys.Send
	epoch := send.Symmetric.Epoch
	rn := format.RecordNumberWith(epoch, conn.Keys.SendNextSegmentSequence)
	seq := conn.Keys.SendNextSegmentSequence // we always send 16-bit seqnums for simplicity. TODO - implement 8-bit seqnums, check if we correctly parse/decrypt them from peer
	conn.Keys.SendNextSegmentSequence++      // does not overflow due to checkSendLimit() above
	log.Printf("constructing ciphertext application with rn={%d,%d}", rn.Epoch(), rn.SeqNum())

	gcm := send.Symmetric.Write
	iv := send.Symmetric.WriteIV
	keys.FillIVSequence(iv[:], seq)

	// format of our encrypted record is fixed. TODO - save on length if last record in datagram
	hdr := format.NewCiphertextRecordHeader(false, true, true, epoch)
	const hdrSize = format.OutgoingCiphertextRecordHeader
	record = append(record, format.PlaintextContentTypeApplicationData)

	padding := len(record) % 4 // test our code with different padding. TODO - remove later
	// max padding max correspond to format.MaxOutgoingCiphertextRecordOverhead
	for i := 0; i != padding+constants.AEADSealSize; i++ {
		record = append(record, 0)
	}

	record[0] = hdr.FirstByte
	binary.BigEndian.PutUint16(record[1:], uint16(seq))
	binary.BigEndian.PutUint16(record[3:], uint16(len(record)-hdrSize))

	encrypted := gcm.Seal(record[hdrSize:hdrSize], iv[:], record[hdrSize:len(record)-constants.AEADSealSize], record[:hdrSize])
	if &encrypted[0] != &record[hdrSize] {
		panic("gcm.Seal reallocated datagram storage")
	}
	if len(encrypted) != len(record[hdrSize:]) {
		panic("gcm.Seal length mismatch")
	}

	if !conn.Keys.DoNotEncryptSequenceNumbers {
		if err := send.Symmetric.EncryptSequenceNumbers(record[1:3], record[hdrSize:]); err != nil {
			panic("cipher text too short when sending")
		}
	}
	//	log.Printf("dtls: ciphertext %d protected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	return record, nil
}
