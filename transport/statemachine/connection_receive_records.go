// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"fmt"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/record"
)

// [rfc9147:4.5.3] we check against AEAD limit, initiate key update well before
// reaching limit, and close connection if limit reached
func (conn *Connection) checkReceiveLimits() error {
	receiveLimit := min(conn.keys.SequenceNumberLimit(), constants.MaxProtectionLimitReceive)
	received := conn.keys.FailedDeprotection + conn.keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
	if conn.keys.NewReceiveKeysSet && received >= constants.ProtectionSoftLimit(receiveLimit) &&
		conn.keys.NewReceiveNextSegmentSequence.GetNextReceivedSeq() != 0 {
		// Remove our old keys to stop attack, but only if we know peer updated keys.
		// Without last condition, as soon as the new keys will be generated after reaching soft limit,
		// they will immediately replace current keys before peer actually updated them, leading to deadlock.
		// TODO - we cannot remove old keys right after first datagram received with the new keys,
		// only because client will retransmit flight [cert..finished] in epoch 2 forever until we ack it,
		// and we cannot ack without decrypting at least seqnum, so we have to remember epoch 2 keys for
		// some time.
		conn.removeOldReceiveKeys()
	}
	// calculate again, because conn.removeOldReceiveKeys() could move keys
	received = conn.keys.FailedDeprotection + conn.keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
	receivedNew := conn.keys.NewReceiveFailedDeprotection + conn.keys.NewReceiveNextSegmentSequence.GetNextReceivedSeq()
	if received >= receiveLimit || receivedNew >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflowNextEpoch
	}
	if conn.keys.NewReceiveKeysSet && receivedNew < constants.ProtectionSoftLimit(receiveLimit) {
		return nil
	}
	if !conn.keys.NewReceiveKeysSet && received < constants.ProtectionSoftLimit(receiveLimit) {
		return nil
	}
	if conn.keys.Receive.Epoch < 3 {
		return nil
	}
	if conn.keyUpdateInProgress() {
		// wait for previous key update to finish, it could be one with updateRequested = false
		return nil
	}
	if conn.keys.RequestedReceiveEpochUpdateIn == conn.keys.Receive.Epoch {
		return nil
	}
	conn.keys.RequestedReceiveEpochUpdateIn = conn.keys.Receive.Epoch
	return conn.keyUpdateStart(true)
}

// returns contentType == 0 (which is impossible due to padding format) with err == nil when replay detected
func (conn *Connection) deprotectLocked(hdr record.Encrypted) ([]byte, record.Number, byte, error) {
	if conn.keys.Receive.Epoch == 0 {
		return nil, record.Number{}, 0, dtlserrors.WarnCannotDecryptInEpoch0
	}
	receivedEpoch := conn.keys.Receive.Epoch
	if conn.keys.NewReceiveKeysSet {
		// Receive.Epoch corresponds to new keys if they are set, and to the
		// old keys otherwise. This is convenient in all places, except here.
		receivedEpoch-- // safe due to check above
	}
	if hdr.MatchesEpoch(receivedEpoch) {
		nextSeq := conn.keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
		recordBody, seq, contentType, err := conn.deprotectWithKeysLocked(conn.keys.Receive.Symmetric, hdr, nextSeq)
		if err != nil {
			// [rfc9147:4.5.3] check against AEAD limit
			conn.keys.FailedDeprotection++
			return nil, record.Number{}, 0, err
		}
		conn.keys.ReceiveNextSegmentSequence.SetNextReceived(seq + 1)
		if conn.keys.ReceiveNextSegmentSequence.IsSetBit(seq) {
			return nil, record.Number{}, 0, nil // replay protection
		}
		conn.keys.ReceiveNextSegmentSequence.SetBit(seq)
		return recordBody, record.NumberWith(receivedEpoch, seq), contentType, nil
	}
	if !conn.keys.NewReceiveKeysSet {
		// simply ignore, probably garbage or keys from previous epoch
		return nil, record.Number{}, 0, dtlserrors.WarnEpochDoesNotMatch
	}
	if !hdr.MatchesEpoch(conn.keys.Receive.Epoch) {
		// simply ignore, probably garbage or keys from previous epoch
		return nil, record.Number{}, 0, dtlserrors.WarnEpochDoesNotMatch
	}
	// We should not believe new epoch bits before we decrypt record successfully,
	// so we have to calculate new keys here. But if we fail decryption, then we
	// either should store new keys, or recompute them on each (attacker's) packet.
	// So, we decided we better store new keys
	nextSeq := conn.keys.NewReceiveNextSegmentSequence.GetNextReceivedSeq()
	recordBody, seq, contentType, err := conn.deprotectWithKeysLocked(conn.keys.NewReceiveKeys, hdr, nextSeq)
	if err != nil {
		// [rfc9147:4.5.3] check against AEAD limit
		conn.keys.NewReceiveFailedDeprotection++
		return nil, record.Number{}, 0, err
	}
	conn.keys.NewReceiveNextSegmentSequence.SetNextReceived(seq + 1)
	if conn.keys.NewReceiveNextSegmentSequence.IsSetBit(seq) {
		return nil, record.Number{}, 0, nil // replay protection
	}
	conn.keys.NewReceiveNextSegmentSequence.SetBit(seq)
	return recordBody, record.NumberWith(conn.keys.Receive.Epoch, seq), contentType, nil
}

func (conn *Connection) deprotectWithKeysLocked(keys ciphersuite.SymmetricKeys, hdr record.Encrypted, expectedSN uint64) (recordBody []byte, seq uint64, contentType byte, err error) {
	if !conn.keys.DoNotEncryptSequenceNumbers {
		mask, err := keys.EncryptSeqMask(hdr.Ciphertext)
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
	decrypted := hdr.Ciphertext[:plaintextSize]
	paddingOffset, contentType := findPaddingOffsetContentType(decrypted) // [rfc8446:5.4]
	if paddingOffset < 0 {
		return nil, seq, 0, dtlserrors.ErrCipherTextAllZeroPadding
	}
	return decrypted[:paddingOffset], seq, contentType, nil
}
