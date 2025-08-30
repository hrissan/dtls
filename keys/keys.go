// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package keys

import (
	"crypto/sha256"
	"hash"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/hkdf"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/replay"
)

type Keys struct {
	// fields sorted to minimize padding
	Send    DirectionKeys
	Receive DirectionKeys

	SendNextSegmentSequence uint64

	// It seems, we need no replay protection for Epoch 0. TODO - investigate..
	ReceiveNextSegmentSequence replay.Window // for Epoch > 0

	SendAcks      replay.Window
	SendAcksEpoch uint16 // we do not want to lose acks immediately  when switching epoch

	// Idea: we have storage 2 sets of keys, keep previous epoch keys for replay window length.
	// But then we need also 2 replay windows, and 2 SendAcks structs.

	// always correspond to Receive.Symmetric.Epoch + 1 if NewReceiveKeysSet is set
	NewReceiveKeys ciphersuite.SymmetricKeys

	FailedDeprotectionCounter               uint64
	FailedDeprotectionCounterNewReceiveKeys uint64 // separate counter for NewReceiveKeys

	// enabled extensions and saves us 50% memory on crypto contexts
	DoNotEncryptSequenceNumbers bool
	// waiting for the next epoch during handshake or key update
	ExpectReceiveEpochUpdate bool
	// we should request update only once per epoch, and this must be separate flag from sendKeyUpdateUpdateRequested
	// otherwise we will request update again after peer's ack, but before actual epoch update
	RequestedReceiveEpochUpdate bool
	// calculate NewReceiveKeys only once
	NewReceiveKeysSet bool
	SuiteID           ciphersuite.ID
}

func (keys *Keys) Suite() ciphersuite.Suite {
	return ciphersuite.GetSuite(keys.SuiteID)
}

func (keys *Keys) AddAck(rn record.Number) {
	if rn.Epoch() < keys.SendAcksEpoch { // peer will resend in a new epoch
		return
	}
	if rn.Epoch() > keys.SendAcksEpoch {
		keys.SendAcksEpoch = rn.Epoch()
		keys.SendAcks.Reset()
	}
	// in epoch 0, we send ack for ServerHello, but not for ClientHello,
	// fmt.Printf("adding ack={%d,%d}\n", rn.Epoch(), rn.SeqNum())
	keys.SendAcks.SetNextReceived(rn.SeqNum() + 1)
	keys.SendAcks.SetBit(rn.SeqNum())
}

func (keys *Keys) SequenceNumberLimit() uint64 {
	return min(keys.Suite().ProtectionLimit(), record.MaxSeq)
}

func ComputeEarlySecret(suite ciphersuite.Suite, psk []byte, extOrResLabel string) (earlySecret ciphersuite.Hash, binderKey ciphersuite.Hash) {
	// [rfc8446:4.2.11.2] PSK Binder
	// Derive-Secret(., "ext binder" | "res binder", "") = binder_key
	// finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
	emptyHash := sha256.Sum256(nil)

	salt := []byte{}
	pskStorage := [32]byte{}
	if len(psk) == 0 {
		psk = pskStorage[:]
	}
	hmacSalt := suite.NewHMAC(salt)
	earlySecret.SetValue(hkdf.Extract(hmacSalt, psk[:]))

	if len(extOrResLabel) != 0 { // optimization
		hmacEarlySecret := suite.NewHMAC(earlySecret.GetValue())
		binderKey.SetValue(deriveSecret(hmacEarlySecret, extOrResLabel, emptyHash[:]))
	}
	return
}

func (keys *Keys) ComputeHandshakeKeys(suite ciphersuite.Suite, serverRole bool, earlySecret ciphersuite.Hash, sharedSecret []byte, trHash []byte) (
	masterSecret [32]byte, handshakeTrafficSecretSend [32]byte, handshakeTrafficSecretReceive [32]byte) {
	emptyHash := sha256.Sum256(nil)

	hmacEarlySecret := suite.NewHMAC(earlySecret.GetValue())

	derivedSecret := deriveSecret(hmacEarlySecret, "derived", emptyHash[:])
	hmacderivedSecret := suite.NewHMAC(derivedSecret)

	handshakeSecret := hkdf.Extract(hmacderivedSecret, sharedSecret)
	hmacHandshakeSecret := suite.NewHMAC(handshakeSecret)

	handshakeTrafficSecretSend = keys.Send.ComputeHandshakeKeys(suite, serverRole, hmacHandshakeSecret, trHash)
	keys.SendNextSegmentSequence = 0

	handshakeTrafficSecretReceive = keys.Receive.ComputeHandshakeKeys(suite, !serverRole, hmacHandshakeSecret, trHash)
	keys.ReceiveNextSegmentSequence.Reset()
	keys.ExpectReceiveEpochUpdate = true

	derivedSecret = deriveSecret(hmacHandshakeSecret, "derived", emptyHash[:])
	hmacderivedSecret = suite.NewHMAC(derivedSecret)
	zeros := [32]byte{}
	masterSecretSlice := hkdf.Extract(hmacderivedSecret, zeros[:])
	copy(masterSecret[:], masterSecretSlice)
	return
}

func (keys *Keys) ComputeApplicationTrafficSecret(suite ciphersuite.Suite, serverRole bool, masterSecret []byte, trHash []byte) {
	keys.Send.ComputeApplicationTrafficSecret(suite, serverRole, masterSecret, trHash)
	keys.Receive.ComputeApplicationTrafficSecret(suite, !serverRole, masterSecret, trHash)
}

func deriveSecret(hmacSecret hash.Hash, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hmacSecret, label, sum, len(sum))
}
