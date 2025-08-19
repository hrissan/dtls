package statemachine

import (
	"math"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
)

func (conn *ConnectionImpl) checkReceiveLimits() error {
	receiveLimit := conn.Keys.SequenceNumberLimit()
	if conn.Keys.FailedDeprotectionCounterNewReceiveKeys >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflowNextEpoch
	}
	// we cannot request update of NewReceiveKeys, but if peer rotates them before
	// error above, we will request update.
	receivedCurrentEpoch := conn.Keys.FailedDeprotectionCounter + conn.Keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
	if receivedCurrentEpoch >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflow
	}
	if conn.Keys.Receive.Symmetric.Epoch < 3 || receivedCurrentEpoch < receiveLimit*3/4 { // simple heuristics
		return nil
	}
	if conn.sendKeyUpdateMessageSeq != 0 {
		// wait for previous key update to finish, it could be one with updateRequested = false
		return nil
	}
	if conn.Keys.RequestedReceiveEpochUpdate {
		return nil
	}
	conn.Keys.RequestedReceiveEpochUpdate = true
	return conn.startKeyUpdate(true)
}

func (conn *ConnectionImpl) deprotectLocked(hdr format.CiphertextRecordHeader, seqNumData []byte, header []byte, body []byte) (decrypted []byte, rn format.RecordNumber, contentType byte, err error) {
	receiver := &conn.Keys.Receive
	var seq uint64
	if hdr.MatchesEpoch(receiver.Symmetric.Epoch) {
		nextSeq := conn.Keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
		decrypted, seq, contentType, err = receiver.Symmetric.Deprotect(hdr, !conn.Keys.DoNotEncryptSequenceNumbers, nextSeq,
			seqNumData, header, body)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			conn.Keys.FailedDeprotectionCounter++
			return
		}
		conn.Keys.ReceiveNextSegmentSequence.SetNextReceived(seq + 1)
		if conn.Keys.ReceiveNextSegmentSequence.IsSetBit(seq) {
			return // replay protection
		}
		conn.Keys.ReceiveNextSegmentSequence.SetBit(seq)
	} else {
		if !conn.Keys.ExpectReceiveEpochUpdate || !hdr.MatchesEpoch(receiver.Symmetric.Epoch+1) {
			return // simply ignore, probably garbage or keys from previous epoch
		}
		// We check here that receiver.Epoch+1 does not overflow, because we increment it below
		if receiver.Symmetric.Epoch == math.MaxUint16 {
			err = dtlserrors.ErrUpdatingKeysWouldOverflowEpoch
			return
		}
		// We should not believe new epoch bits before we decrypt record successfully,
		// so we have to calculate new keys here. But if we fail decryption, then we
		// either should store new keys, or recompute them on each (attacker's) packet.
		// So, we decided we better store new keys
		if !conn.Keys.NewReceiveKeysSet {
			conn.Keys.NewReceiveKeysSet = true
			conn.Keys.NewReceiveKeys.Epoch = receiver.Symmetric.Epoch + 1
			conn.Keys.NewReceiveKeys.ComputeKeys(receiver.ApplicationTrafficSecret[:])
			conn.Keys.FailedDeprotectionCounterNewReceiveKeys = 0
			receiver.ComputeNextApplicationTrafficSecret(!conn.RoleServer) // next application traffic secret is calculated from the previous one
		}
		decrypted, seq, contentType, err = conn.Keys.NewReceiveKeys.Deprotect(hdr, !conn.Keys.DoNotEncryptSequenceNumbers, 0,
			seqNumData, header, body)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			conn.Keys.FailedDeprotectionCounterNewReceiveKeys++
			return
		}
		conn.Keys.ExpectReceiveEpochUpdate = false
		receiver.Symmetric = conn.Keys.NewReceiveKeys // epoch is also copied
		conn.Keys.ReceiveNextSegmentSequence.Reset()
		conn.Keys.ReceiveNextSegmentSequence.SetNextReceived(seq + 1)
		// always unique, do not check
		conn.Keys.ReceiveNextSegmentSequence.SetBit(seq)
		conn.Keys.FailedDeprotectionCounter = conn.Keys.FailedDeprotectionCounterNewReceiveKeys
		conn.Keys.NewReceiveKeys = keys.SymmetricKeys{} // remove alias
		conn.Keys.NewReceiveKeysSet = false
		conn.Keys.FailedDeprotectionCounterNewReceiveKeys = 0
		conn.Keys.RequestedReceiveEpochUpdate = false
	}
	rn = format.RecordNumberWith(receiver.Symmetric.Epoch, seq)
	return
}
