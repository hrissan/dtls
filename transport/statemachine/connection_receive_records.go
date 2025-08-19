package statemachine

import (
	"math"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/keys"
	"github.com/hrissan/tinydtls/record"
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

// returns contentType == 0 (which is impossible due to padding format) with err == nil when replay detected
func (conn *ConnectionImpl) deprotectLocked(hdr record.Ciphertext) ([]byte, record.Number, byte, error) {
	receiver := &conn.Keys.Receive
	if hdr.MatchesEpoch(receiver.Symmetric.Epoch) {
		nextSeq := conn.Keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
		decrypted, seq, contentType, err := receiver.Symmetric.Deprotect(hdr, !conn.Keys.DoNotEncryptSequenceNumbers, nextSeq)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			conn.Keys.FailedDeprotectionCounter++
			return nil, record.Number{}, 0, err
		}
		conn.Keys.ReceiveNextSegmentSequence.SetNextReceived(seq + 1)
		if conn.Keys.ReceiveNextSegmentSequence.IsSetBit(seq) {
			return nil, record.Number{}, 0, nil // replay protection
		}
		conn.Keys.ReceiveNextSegmentSequence.SetBit(seq)
		return decrypted, record.NumberWith(receiver.Symmetric.Epoch, seq), contentType, nil
	}
	if !conn.Keys.ExpectReceiveEpochUpdate || !hdr.MatchesEpoch(receiver.Symmetric.Epoch+1) {
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
	if !conn.Keys.NewReceiveKeysSet {
		conn.Keys.NewReceiveKeysSet = true
		conn.Keys.NewReceiveKeys.Epoch = receiver.Symmetric.Epoch + 1
		conn.Keys.NewReceiveKeys.ComputeKeys(receiver.ApplicationTrafficSecret[:])
		conn.Keys.FailedDeprotectionCounterNewReceiveKeys = 0
		receiver.ComputeNextApplicationTrafficSecret(!conn.RoleServer) // next application traffic secret is calculated from the previous one
	}
	decrypted, seq, contentType, err := conn.Keys.NewReceiveKeys.Deprotect(hdr, !conn.Keys.DoNotEncryptSequenceNumbers, 0)
	if err != nil {
		// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
		conn.Keys.FailedDeprotectionCounterNewReceiveKeys++
		return nil, record.Number{}, 0, err
	}
	conn.Keys.ExpectReceiveEpochUpdate = false

	receiver.Symmetric = conn.Keys.NewReceiveKeys   // epoch is also copied
	conn.Keys.NewReceiveKeys = keys.SymmetricKeys{} // remove alias
	conn.Keys.NewReceiveKeysSet = false

	conn.Keys.ReceiveNextSegmentSequence.Reset()
	conn.Keys.ReceiveNextSegmentSequence.SetNextReceived(seq + 1)
	if conn.Keys.ReceiveNextSegmentSequence.IsSetBit(seq) {
		panic("first record in a new epoch is always unique")
	}
	conn.Keys.ReceiveNextSegmentSequence.SetBit(seq)

	conn.Keys.FailedDeprotectionCounter = conn.Keys.FailedDeprotectionCounterNewReceiveKeys
	conn.Keys.FailedDeprotectionCounterNewReceiveKeys = 0

	conn.Keys.RequestedReceiveEpochUpdate = false // so we can request in the next epoch
	return decrypted, record.NumberWith(receiver.Symmetric.Epoch, seq), contentType, nil
}
