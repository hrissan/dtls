// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

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
	if conn.keys.ReceiveEpoch == 0 {
		return dtlserrors.WarnCannotDecryptInEpoch0
	}
	hardLimit := min(conn.keys.SequenceNumberLimit(), constants.MaxProtectionLimitReceive)
	softLimit := constants.ProtectionSoftLimit(hardLimit)

	received := conn.keys.FailedDeprotection + conn.keys.ReceiveNextSeq.GetNextReceivedSeq()
	receivedNew := conn.keys.NewReceiveFailedDeprotection + conn.keys.NewReceiveNextSeq.GetNextReceivedSeq()
	if received >= hardLimit || receivedNew >= hardLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflowNextEpoch
	}
	if conn.keys.ReceiveEpoch < 3 { // no KeyUpdate before epoch 3
		return nil
	}
	if (received >= softLimit || receivedNew >= softLimit) && conn.keys.ReceiveEpoch == 3 && conn.keys.NewReceiveKeysSet {
		conn.removeOldReceiveKeys() // [2] [3] -> [3] [.] we keep epoch 2 keys for the long time to send acks
		return nil
	}
	if received < softLimit || conn.keys.NewReceiveKeysSet {
		return nil
	}
	// [3+] [.]
	if conn.keyUpdateInProgress() {
		// wait for previous key update to finish, it could be one with updateRequested = false
		return nil
	}
	if conn.keys.RequestedReceiveEpochUpdateIn == conn.keys.ReceiveEpoch {
		return nil
	}
	conn.keys.RequestedReceiveEpochUpdateIn = conn.keys.ReceiveEpoch
	return conn.keyUpdateStart(true)
}

// returns contentType == 0 (which is impossible due to padding format) with err == nil when replay detected
func (conn *Connection) deprotectLocked(hdr record.Encrypted) ([]byte, record.Number, byte, error) {
	if conn.keys.ReceiveEpoch == 0 {
		return nil, record.Number{}, 0, dtlserrors.WarnCannotDecryptInEpoch0
	}
	receivedEpoch := conn.keys.ReceiveEpoch
	if conn.keys.NewReceiveKeysSet {
		// Receive.Epoch corresponds to new keys if they are set, and to the
		// old keys otherwise. This is convenient in all places, except here.
		receivedEpoch-- // safe due to check above
	}
	if hdr.MatchesEpoch(receivedEpoch) {
		nextSeq := conn.keys.ReceiveNextSeq.GetNextReceivedSeq()
		recordBody, seq, contentType, err := conn.deprotectWithKeysLocked(conn.keys.ReceiveSymmetric, hdr, nextSeq)
		if err != nil {
			// [rfc9147:4.5.3] check against AEAD limit
			conn.keys.FailedDeprotection++
			return nil, record.Number{}, 0, err
		}
		conn.keys.ReceiveNextSeq.SetNextReceived(seq + 1)
		if conn.keys.ReceiveNextSeq.IsSetBit(seq) {
			return nil, record.Number{}, 0, nil // replay protection
		}
		conn.keys.ReceiveNextSeq.SetBit(seq)

		return recordBody, record.NumberWith(receivedEpoch, seq), contentType, nil
	}
	if !conn.keys.NewReceiveKeysSet {
		// simply ignore, probably garbage or keys from previous epoch
		return nil, record.Number{}, 0, dtlserrors.WarnEpochDoesNotMatch
	}
	if !hdr.MatchesEpoch(conn.keys.ReceiveEpoch) {
		// simply ignore, probably garbage or keys from previous epoch
		return nil, record.Number{}, 0, dtlserrors.WarnEpochDoesNotMatch
	}
	// We should not believe new epoch bits before we decrypt record successfully,
	// so we have to calculate new keys here. But if we fail decryption, then we
	// either should store new keys, or recompute them on each (attacker's) packet.
	// So, we decided we better store new keys
	nextSeq := conn.keys.NewReceiveNextSeq.GetNextReceivedSeq()
	recordBody, seq, contentType, err := conn.deprotectWithKeysLocked(conn.keys.NewReceiveSymmetric, hdr, nextSeq)
	if err != nil {
		// [rfc9147:4.5.3] check against AEAD limit
		conn.keys.NewReceiveFailedDeprotection++
		return nil, record.Number{}, 0, err
	}
	conn.keys.NewReceiveNextSeq.SetNextReceived(seq + 1)
	if conn.keys.NewReceiveNextSeq.IsSetBit(seq) {
		return nil, record.Number{}, 0, nil // replay protection
	}
	conn.keys.NewReceiveNextSeq.SetBit(seq)
	if conn.keys.ReceiveEpoch > 3 { //  && conn.keys.NewReceiveKeysSet
		// [3] [4] -> [4] [.]
		conn.removeOldReceiveKeys()
	}
	return recordBody, record.NumberWith(conn.keys.ReceiveEpoch, seq), contentType, nil
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
