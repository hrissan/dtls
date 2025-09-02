// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package keys

import (
	"hash"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/replay"
)

type Keys struct {
	// fields sorted to minimize padding
	SendApplicationTrafficSecret ciphersuite.Hash // we need to keep this for key update
	SendEpoch                    uint16

	ReceiveApplicationTrafficSecret ciphersuite.Hash // we need to keep this for key update
	ReceiveEpoch                    uint16

	ReceiveSymmetric   ciphersuite.SymmetricKeys
	ReceiveNextSeq     replay.Window // for Epoch > 0
	FailedDeprotection uint64

	// We store 2 sets of symmetric keys, in case of epoch 2 from client we must actually
	// keep replay window and need successful deprotection of records from both epoch 2 and 3.
	// We cannot do anything about it (in ideal world, client [cert..finished] flight would use epoch 3, not 2),
	// so we simply adapt to this stupidity, wasting space and brain cells.
	// ReceiveEpoch corresponds to new keys, if NewReceiveKeysSet is set, or to old keys if not.
	NewReceiveSymmetric          ciphersuite.SymmetricKeys
	NewReceiveNextSeq            replay.Window
	NewReceiveFailedDeprotection uint64 // separate counter for NewReceiveSymmetric

	// It seems, we need no replay protection for Epoch 0. TODO - investigate..

	SendSymmetric ciphersuite.SymmetricKeys
	SendNextSeq   uint64

	SendAcks      replay.Window
	SendAcksEpoch uint16 // we do not want to lose acks immediately  when switching epoch

	SuiteID ciphersuite.ID

	// enabled extensions and saves us 50% memory on crypto contexts
	DoNotEncryptSequenceNumbers bool
	// we should request update only once per epoch, and this must be separate flag from sendKeyUpdateUpdateRequested
	// otherwise we will request update again after peer's ack, but before actual epoch update
	RequestedReceiveEpochUpdateIn uint16
	// calculate NewReceiveSymmetric only once
	NewReceiveKeysSet bool // we do not deallocate NewReceiveSymmetric, so cannot use NewReceiveSymmetric != nil
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
	emptyHash := suite.EmptyHash()

	hmacSalt := suite.NewHMAC(nil) // empty salt

	if len(psk) != 0 {
		earlySecret = ciphersuite.HKDFExtract(hmacSalt, psk)
	} else {
		var zeroHash ciphersuite.Hash
		zeroHash.SetZero(hmacSalt.Size())
		earlySecret = ciphersuite.HKDFExtract(hmacSalt, zeroHash.GetValue())
	}

	if len(extOrResLabel) != 0 { // optimization
		hmacEarlySecret := suite.NewHMAC(earlySecret.GetValue())
		binderKey = deriveSecret(hmacEarlySecret, extOrResLabel, emptyHash)
	}
	return
}

func (keys *Keys) ComputeHandshakeKeys(suite ciphersuite.Suite, serverRole bool, earlySecret ciphersuite.Hash, sharedSecret []byte, trHash ciphersuite.Hash) (
	masterSecret ciphersuite.Hash, handshakeTrafficSecretSend ciphersuite.Hash, handshakeTrafficSecretReceive ciphersuite.Hash) {
	emptyHash := suite.EmptyHash()

	hmacEarlySecret := suite.NewHMAC(earlySecret.GetValue())

	derivedSecret := deriveSecret(hmacEarlySecret, "derived", emptyHash)
	hmacderivedSecret := suite.NewHMAC(derivedSecret.GetValue())

	handshakeSecret := ciphersuite.HKDFExtract(hmacderivedSecret, sharedSecret)
	hmacHandshakeSecret := suite.NewHMAC(handshakeSecret.GetValue())

	if keys.SendEpoch != 0 || keys.ReceiveEpoch != 0 {
		panic("handshake keys state machine violation")
	}
	keys.SendEpoch = 2
	keys.ReceiveEpoch = 2

	handshakeTrafficSecretSend = ComputeHandshakeKeys(serverRole, hmacHandshakeSecret, trHash)
	suite.ResetSymmetricKeys(&keys.SendSymmetric, handshakeTrafficSecretSend)

	keys.SendNextSeq = 0

	handshakeTrafficSecretReceive = ComputeHandshakeKeys(!serverRole, hmacHandshakeSecret, trHash)
	suite.ResetSymmetricKeys(&keys.ReceiveSymmetric, handshakeTrafficSecretReceive)

	keys.ReceiveNextSeq.Reset()

	derivedSecret = deriveSecret(hmacHandshakeSecret, "derived", emptyHash)
	hmacderivedSecret = suite.NewHMAC(derivedSecret.GetValue())
	var zeroHash ciphersuite.Hash
	zeroHash.SetZero(hmacderivedSecret.Size())
	masterSecret = ciphersuite.HKDFExtract(hmacderivedSecret, zeroHash.GetValue())
	return
}

func (keys *Keys) ComputeApplicationTrafficSecret(suite ciphersuite.Suite, serverRole bool, masterSecret ciphersuite.Hash, trHash ciphersuite.Hash) {
	keys.SendApplicationTrafficSecret = ComputeApplicationTrafficSecret(suite, serverRole, masterSecret, trHash)
	keys.ReceiveApplicationTrafficSecret = ComputeApplicationTrafficSecret(suite, !serverRole, masterSecret, trHash)
}

func deriveSecret(hmacSecret hash.Hash, label string, sum ciphersuite.Hash) (result ciphersuite.Hash) {
	result.SetZero(sum.Len())
	ciphersuite.HKDFExpandLabel(result.GetValue(), hmacSecret, label, sum.GetValue())
	return result
}
