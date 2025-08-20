package statemachine

import (
	"math"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/keys"
	"github.com/hrissan/tinydtls/record"
)

func (conn *ConnectionImpl) checkReceiveLimits() error {
	receiveLimit := conn.keys.SequenceNumberLimit()
	if conn.keys.FailedDeprotectionCounterNewReceiveKeys >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflowNextEpoch
	}
	// we cannot request update of NewReceiveKeys, but if peer rotates them before
	// error above, we will request update.
	receivedCurrentEpoch := conn.keys.FailedDeprotectionCounter + conn.keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
	if receivedCurrentEpoch >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflow
	}
	if conn.keys.Receive.Symmetric.Epoch < 3 || receivedCurrentEpoch < receiveLimit*3/4 { // simple heuristics
		return nil
	}
	if conn.sendKeyUpdateMessageSeq != 0 {
		// wait for previous key update to finish, it could be one with updateRequested = false
		return nil
	}
	if conn.keys.RequestedReceiveEpochUpdate {
		return nil
	}
	conn.keys.RequestedReceiveEpochUpdate = true
	return conn.startKeyUpdate(true)
}

// returns contentType == 0 (which is impossible due to padding format) with err == nil when replay detected
func (conn *ConnectionImpl) deprotectLocked(hdr record.Ciphertext) ([]byte, record.Number, byte, error) {
	receiver := &conn.keys.Receive
	if hdr.MatchesEpoch(receiver.Symmetric.Epoch) {
		nextSeq := conn.keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
		decrypted, seq, contentType, err := receiver.Symmetric.Deprotect(hdr, !conn.keys.DoNotEncryptSequenceNumbers, nextSeq)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			conn.keys.FailedDeprotectionCounter++
			return nil, record.Number{}, 0, err
		}
		conn.keys.ReceiveNextSegmentSequence.SetNextReceived(seq + 1)
		if conn.keys.ReceiveNextSegmentSequence.IsSetBit(seq) {
			return nil, record.Number{}, 0, nil // replay protection
		}
		conn.keys.ReceiveNextSegmentSequence.SetBit(seq)
		return decrypted, record.NumberWith(receiver.Symmetric.Epoch, seq), contentType, nil
	}
	if !conn.keys.ExpectReceiveEpochUpdate || !hdr.MatchesEpoch(receiver.Symmetric.Epoch+1) {
		// simply ignore, probably garbage or keys from previous epoch
		return nil, record.Number{}, 0, dtlserrors.ErrEpochDoesNotMatch
	}
	// We check here that receiver.Epoch+1 does not overflow, because we increment it below
	if receiver.Symmetric.Epoch == math.MaxUint16 {
		return nil, record.Number{}, 0, dtlserrors.ErrUpdatingKeysWouldOverflowEpoch
	}
	// We should not believe new epoch bits before we decrypt record successfully,
	// so we have to calculate new keys here. But if we fail decryption, then we
	// either should store new keys, or recompute them on each (attacker's) packet.
	// So, we decided we better store new keys
	if !conn.keys.NewReceiveKeysSet {
		conn.keys.NewReceiveKeysSet = true
		conn.keys.NewReceiveKeys.Epoch = receiver.Symmetric.Epoch + 1
		conn.keys.NewReceiveKeys.ComputeKeys(receiver.ApplicationTrafficSecret[:])
		conn.keys.FailedDeprotectionCounterNewReceiveKeys = 0
		receiver.ComputeNextApplicationTrafficSecret(!conn.roleServer) // next application traffic secret is calculated from the previous one
	}
	decrypted, seq, contentType, err := conn.keys.NewReceiveKeys.Deprotect(hdr, !conn.keys.DoNotEncryptSequenceNumbers, 0)
	if err != nil {
		// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
		conn.keys.FailedDeprotectionCounterNewReceiveKeys++
		return nil, record.Number{}, 0, err
	}
	conn.keys.ExpectReceiveEpochUpdate = false

	receiver.Symmetric = conn.keys.NewReceiveKeys   // epoch is also copied
	conn.keys.NewReceiveKeys = keys.SymmetricKeys{} // remove alias
	conn.keys.NewReceiveKeysSet = false

	conn.keys.ReceiveNextSegmentSequence.Reset()
	conn.keys.ReceiveNextSegmentSequence.SetNextReceived(seq + 1)
	if conn.keys.ReceiveNextSegmentSequence.IsSetBit(seq) {
		panic("first record in a new epoch is always unique")
	}
	conn.keys.ReceiveNextSegmentSequence.SetBit(seq)

	conn.keys.FailedDeprotectionCounter = conn.keys.FailedDeprotectionCounterNewReceiveKeys
	conn.keys.FailedDeprotectionCounterNewReceiveKeys = 0

	conn.keys.RequestedReceiveEpochUpdate = false // so we can request in the next epoch
	return decrypted, record.NumberWith(receiver.Symmetric.Epoch, seq), contentType, nil
}
