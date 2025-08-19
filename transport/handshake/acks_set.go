package handshake

import (
	"encoding/binary"
	"math"
	"slices"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/transport/options"
)

// TODO - not used anymore, remove later

type AcksSet struct {
	// sorted before sending, elements are at the back
	// sendAcks     [constants.MaxSendAcks]format.RecordNumber - storage is external, due to no generic by size
	sendAcksSize int
}

func (a *AcksSet) Clear() {
	a.sendAcksSize = 0
}

func (a *AcksSet) Size() int {
	return a.sendAcksSize
}

func (a *AcksSet) Add(storage []format.RecordNumber, rn format.RecordNumber) {
	sendAcksOffset := len(storage) - a.sendAcksSize
	if sendAcksOffset == 0 {
		return
	}
	for _, ack := range storage[sendAcksOffset:] { // linear search must be fast here
		if ack == rn {
			return
		}
	}
	a.sendAcksSize++
	storage[sendAcksOffset-1] = rn
	return
}

func (a *AcksSet) PopSorted(storage []format.RecordNumber, maxCount int) []format.RecordNumber {
	sendAcksOffset := len(storage) - a.sendAcksSize
	// sort all first, otherwise we get random set
	slices.SortFunc(storage[sendAcksOffset:], format.RecordNumberCmp)
	a.sendAcksSize -= maxCount
	return storage[sendAcksOffset : sendAcksOffset+maxCount]
}

func (a *AcksSet) AddFrom(storage []format.RecordNumber, other *AcksSet, otherStorage []format.RecordNumber) {
	otherAcks := other.PopSorted(otherStorage, min(other.Size(), len(storage)))
	for _, ack := range otherAcks {
		a.Add(storage[:], ack)
	}
}

func (a *AcksSet) HasDataToSend(conn *ConnectionImpl) bool {
	return a.Size() != 0 && conn.Keys.Send.Symmetric.Epoch != 0 // We send only encrypted acks
}

func (a *AcksSet) ConstructDatagram(storage []format.RecordNumber, conn *ConnectionImpl, datagram []byte) (int, error) {
	if !a.HasDataToSend(conn) {
		return 0, nil
	}
	acksSpace := len(datagram) - format.MessageAckHeaderSize - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
	if acksSpace < format.MessageAckRecordNumberSize { // not a single one fits
		return 0, nil
	}
	acksCount := min(a.Size(), acksSpace/format.MessageAckRecordNumberSize)
	if acksSpace < constants.MinFragmentBodySize && acksCount != a.Size() {
		return 0, nil // do not send tiny records at the end of datagram
	}
	sendAcks := a.PopSorted(storage, acksCount)

	da, err := conn.constructCiphertextAck(datagram[:0], sendAcks)
	if err != nil {
		return 0, err
	}
	if len(da) > len(datagram) {
		panic("ciphertext ack record construction length invariant failed")
	}
	return len(da), nil
}

// TODO - move out
func (conn *ConnectionImpl) ReceiveAcks(opts *options.TransportOptions, insideBody []byte) {
	for ; len(insideBody) >= format.MessageAckRecordNumberSize; insideBody = insideBody[format.MessageAckRecordNumberSize:] {
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
		if conn.sendNewSessionTicketRN != (format.RecordNumber{}) && conn.sendNewSessionTicketRN == rn {
			conn.sendNewSessionTicketRN = format.RecordNumber{}
			conn.sendNewSessionTicketMessageSeq = 0
		}
	}
}
