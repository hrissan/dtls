package handshake

import (
	"encoding/binary"
	"math"
	"slices"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/format"
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
