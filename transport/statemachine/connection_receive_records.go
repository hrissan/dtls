// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"fmt"
	"math"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
)

// [rfc9147:4.5.3] we check against AEAD limit, initiate key update well before
// reaching limit, and close connection if limit reached
func (conn *Connection) checkReceiveLimits() error {
	receiveLimit := min(conn.keys.SequenceNumberLimit(), constants.MaxProtectionLimitReceive)
	if conn.keys.FailedDeprotectionCounterNewReceiveKeys >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflowNextEpoch
	}
	// we cannot request update of NewReceiveKeys, but if peer rotates them before
	// error above, we will request update.
	receivedCurrentEpoch := conn.keys.FailedDeprotectionCounter + conn.keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
	if receivedCurrentEpoch >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflow
	}
	if conn.keys.ReceiveEpoch < 3 || receivedCurrentEpoch < receiveLimit*3/4 { // simple heuristics
		return nil
	}
	if conn.keyUpdateInProgress() {
		// wait for previous key update to finish, it could be one with updateRequested = false
		return nil
	}
	if conn.keys.RequestedReceiveEpochUpdate {
		return nil
	}
	conn.keys.RequestedReceiveEpochUpdate = true
	return conn.keyUpdateStart(true)
}

// returns contentType == 0 (which is impossible due to padding format) with err == nil when replay detected
func (conn *Connection) deprotectLocked(hdr record.Ciphertext) ([]byte, record.Number, byte, error) {
	receiver := &conn.keys.Receive
	if conn.keys.ReceiveEpoch == 0 {
		return nil, record.Number{}, 0, dtlserrors.WarnCannotDecryptInEpoch0
	}
	if hdr.MatchesEpoch(conn.keys.ReceiveEpoch) {
		nextSeq := conn.keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
		recordBody, seq, contentType, err := conn.deprotectWithKeysLocked(receiver.Symmetric, hdr, nextSeq)
		if err != nil {
			// [rfc9147:4.5.3] check against AEAD limit
			conn.keys.FailedDeprotectionCounter++
			return nil, record.Number{}, 0, err
		}
		conn.keys.ReceiveNextSegmentSequence.SetNextReceived(seq + 1)
		if conn.keys.ReceiveNextSegmentSequence.IsSetBit(seq) {
			return nil, record.Number{}, 0, nil // replay protection
		}
		conn.keys.ReceiveNextSegmentSequence.SetBit(seq)
		return recordBody, record.NumberWith(conn.keys.ReceiveEpoch, seq), contentType, nil
	}
	if !conn.keys.ExpectReceiveEpochUpdate || !hdr.MatchesEpoch(conn.keys.ReceiveEpoch+1) {
		// simply ignore, probably garbage or keys from previous epoch
		return nil, record.Number{}, 0, dtlserrors.WarnEpochDoesNotMatch
	}
	// We check here that receiver.Epoch+1 does not overflow, because we increment it below
	if conn.keys.ReceiveEpoch == math.MaxUint16 {
		return nil, record.Number{}, 0, dtlserrors.ErrUpdatingKeysWouldOverflowEpoch
	}
	// We should not believe new epoch bits before we decrypt record successfully,
	// so we have to calculate new keys here. But if we fail decryption, then we
	// either should store new keys, or recompute them on each (attacker's) packet.
	// So, we decided we better store new keys
	if !conn.keys.NewReceiveKeysSet {
		conn.keys.NewReceiveKeysSet = true
		conn.keys.Suite().ResetSymmetricKeys(&conn.keys.NewReceiveKeys, receiver.ApplicationTrafficSecret)
		conn.keys.FailedDeprotectionCounterNewReceiveKeys = 0
		receiver.ComputeNextApplicationTrafficSecret(conn.keys.Suite(), "receive")
	}
	recordBody, seq, contentType, err := conn.deprotectWithKeysLocked(conn.keys.NewReceiveKeys, hdr, 0)
	if err != nil {
		// [rfc9147:4.5.3] check against AEAD limit
		conn.keys.FailedDeprotectionCounterNewReceiveKeys++
		return nil, record.Number{}, 0, err
	}
	conn.keys.ExpectReceiveEpochUpdate = false

	// do not free memory, suite will update keys inplace on the next update
	receiver.Symmetric, conn.keys.NewReceiveKeys = conn.keys.NewReceiveKeys, receiver.Symmetric
	conn.keys.ReceiveEpoch++
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
	return recordBody, record.NumberWith(conn.keys.ReceiveEpoch, seq), contentType, nil
}

func (conn *Connection) deprotectWithKeysLocked(keys ciphersuite.SymmetricKeys, hdr record.Ciphertext, expectedSN uint64) (recordBody []byte, seq uint64, contentType byte, err error) {
	if !conn.keys.DoNotEncryptSequenceNumbers {
		mask, err := keys.EncryptSeqMask(hdr.Body)
		if err != nil {
			return nil, 0, 0, err
		}
		encryptSequenceNumbers(hdr.SeqNum, mask)
	}
	decryptedSeqData, seq := hdr.ClosestSequenceNumber(hdr.SeqNum, expectedSN)
	fmt.Printf("decrypted SN: %d, closest: %d\n", decryptedSeqData, seq)

	plaintextSize, err := keys.AEADDecrypt(hdr, seq)
	if err != nil {
		return nil, seq, 0, err
	}
	decrypted := hdr.Body[:plaintextSize]
	paddingOffset, contentType := findPaddingOffsetContentType(decrypted) // [rfc8446:5.4]
	if paddingOffset < 0 {
		return nil, seq, 0, dtlserrors.ErrCipherTextAllZeroPadding
	}
	return decrypted[:paddingOffset], seq, contentType, nil
}
