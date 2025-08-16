package handshake

import (
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
