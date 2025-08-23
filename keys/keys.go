// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"hash"

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

	NewReceiveKeys SymmetricKeys // always correspond to Receive.Symmetric.Epoch + 1

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
	// when we protect or deprotect 3/4 of 2^exp packets, we ask for KeyUpdate
	// if peer does not respond quickly. and we reach 2^exp, we close connection for good
	SequenceNumberLimitExp byte
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
	limitExp := keys.SequenceNumberLimitExp
	if limitExp < 5 {
		panic("do not set limitExp = 4 even for tests, as key update reaches hard limit before epoch will advance")
	}
	// with limitExp = 5 and very few packets you can continuously test key update state machine.
	if limitExp > 48 {
		// Our implementation pack 16-bit epoch with 48-bit sequence number for efficient storage.
		// So we must prevent sequence number from ever reaching this limit.
		// See for example record.Number
		// Also, we must prevent overflow below.
		limitExp = 48
	}
	return (uint64(1) << limitExp) - 1 // -1 gives us margin in case we actually store nextSeqNum in 48-bit field somewhere (we should not)
}

func NewAesCipher(key []byte) cipher.Block {
	c, err := aes.NewCipher(key)
	if err != nil {
		panic("aes.NewCipher fails " + err.Error())
	}
	return c
}

func NewGCMCipher(block cipher.Block) cipher.AEAD {
	c, err := cipher.NewGCM(block)
	if err != nil {
		panic("cipher.NewGCM fails " + err.Error())
	}
	return c
}

func (keys *Keys) ComputeHandshakeKeys(serverRole bool, sharedSecret []byte, trHash []byte) (
	masterSecret [32]byte, handshakeTrafficSecretSend [32]byte, handshakeTrafficSecretReceive [32]byte) {
	hasher := sha256.New()
	emptyHash := sha256.Sum256(nil)

	salt := []byte{}
	psk := [32]byte{}
	earlySecret := hkdf.Extract(hasher, salt, psk[:])

	derivedSecret := deriveSecret(hasher, earlySecret, "derived", emptyHash[:])
	handshakeSecret := hkdf.Extract(hasher, derivedSecret, sharedSecret)

	handshakeTrafficSecretSend = keys.Send.ComputeHandshakeKeys(serverRole, handshakeSecret, trHash)
	keys.SendNextSegmentSequence = 0

	handshakeTrafficSecretReceive = keys.Receive.ComputeHandshakeKeys(!serverRole, handshakeSecret, trHash)
	keys.ReceiveNextSegmentSequence.Reset()
	keys.ExpectReceiveEpochUpdate = true

	derivedSecret = deriveSecret(hasher, handshakeSecret, "derived", emptyHash[:])
	zeros := [32]byte{}
	masterSecretSlice := hkdf.Extract(hasher, derivedSecret, zeros[:])
	copy(masterSecret[:], masterSecretSlice)
	return
}

func (keys *Keys) ComputeApplicationTrafficSecret(serverRole bool, masterSecret []byte, trHash []byte) {
	keys.Send.ComputeApplicationTrafficSecret(serverRole, masterSecret, trHash)
	keys.Receive.ComputeApplicationTrafficSecret(!serverRole, masterSecret, trHash)
}

func deriveSecret(hasher hash.Hash, secret []byte, label string, sum []byte) []byte {
	return hkdf.ExpandLabel(hasher, secret, label, sum, len(sum))
}
