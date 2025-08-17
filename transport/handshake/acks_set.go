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

type AcksSet struct {
	// sorted before sending, elements are at the back
	sendAcks     [constants.MaxSendAcks]format.RecordNumber
	sendAcksSize int
}

func (a *AcksSet) Clear() {
	a.sendAcksSize = 0
}

func (a *AcksSet) Size() int {
	return a.sendAcksSize
}

func (a *AcksSet) Add(rn format.RecordNumber) {
	sendAcksOffset := len(a.sendAcks) - a.sendAcksSize
	if sendAcksOffset == 0 {
		return
	}
	for _, ack := range a.sendAcks[sendAcksOffset:] {
		if ack == rn {
			return
		}
	}
	a.sendAcksSize++
	a.sendAcks[sendAcksOffset-1] = rn
}

func (a *AcksSet) PopSorted(maxCount int) []format.RecordNumber {
	sendAcksOffset := len(a.sendAcks) - a.sendAcksSize
	// sort all first, otherwise we get random set
	slices.SortFunc(a.sendAcks[sendAcksOffset:], format.RecordNumberCmp)
	a.sendAcksSize -= maxCount
	return a.sendAcks[sendAcksOffset : sendAcksOffset+maxCount]
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
		if conn.sendKeyUpdateRN != (format.RecordNumber{}) && conn.sendKeyUpdateRN == rn {
			conn.sendKeyUpdateRN = format.RecordNumber{}
			conn.sendKeyUpdate = false
		}
		if conn.sendNewSessionTicketRN != (format.RecordNumber{}) && conn.sendNewSessionTicketRN == rn {
			conn.sendNewSessionTicketRN = format.RecordNumber{}
			conn.sendNewSessionTicket = false
		}
	}
}

func (a *AcksSet) HasDataToSend(conn *ConnectionImpl) bool {
	return a.Size() != 0 && conn.Keys.Send.Symmetric.Epoch != 0 // We send only encrypted acks
}

func (a *AcksSet) ConstructDatagram(conn *ConnectionImpl, datagram []byte) (datagramSize int) {
	if !a.HasDataToSend(conn) {
		return
	}
	acksSpace := len(datagram) - datagramSize - format.MessageAckHeaderSize - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
	if acksSpace < format.MessageAckRecordNumberSize { // not a single one fits
		return
	}
	acksCount := min(a.Size(), acksSpace/format.MessageAckRecordNumberSize)
	if acksSpace < constants.MinFragmentBodySize && acksCount != a.Size() {
		return // do not send tiny records at the end of datagram
	}
	sendAcks := a.PopSorted(acksCount)

	da := conn.constructCiphertextAck(datagram[datagramSize:datagramSize], sendAcks)

	if len(da) > len(datagram[datagramSize:]) {
		panic("ciphertext ack record construction length invariant failed")
	}
	datagramSize += len(da)
	return
}
