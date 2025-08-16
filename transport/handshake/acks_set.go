package handshake

import (
	"encoding/binary"
	"math"
	"slices"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/format"
)

type AcksSet struct {
	sendAcks       [constants.MaxSendAcks]format.RecordNumber // sorted before sending
	sendAcksOffset int                                        // this is reversed queue
}

func (a *AcksSet) Clear() {
	a.sendAcksOffset = constants.MaxSendAcks
}

func (a *AcksSet) Size() int {
	return constants.MaxSendAcks - a.sendAcksOffset
}

func (a *AcksSet) Add(rn format.RecordNumber) {
	if a.sendAcksOffset == 0 {
		return
	}
	for _, ack := range a.sendAcks[a.sendAcksOffset:] {
		if ack == rn {
			return
		}
	}
	a.sendAcksOffset--
	a.sendAcks[a.sendAcksOffset] = rn
}

func (a *AcksSet) PopSorted(maxCount int) []format.RecordNumber {
	// sort all first, otherwise we get random set
	slices.SortFunc(a.sendAcks[a.sendAcksOffset:], format.RecordNumberCmp)
	result := a.sendAcks[a.sendAcksOffset : a.sendAcksOffset+maxCount]
	a.sendAcksOffset += maxCount
	return result
}

func (conn *ConnectionImpl) ReceiveAcks(insideBody []byte) (registerInSender bool) {
	for ; len(insideBody) >= format.MessageAckRecordNumberSize; insideBody = insideBody[format.MessageAckRecordNumberSize:] {
		epoch := binary.BigEndian.Uint64(insideBody)
		seq := binary.BigEndian.Uint64(insideBody[8:])
		if epoch > math.MaxUint16 {
			// TODO - alert?
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
	return
}
