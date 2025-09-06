// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlscore

import (
	"fmt"
	"math"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/keys"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/replay"
)

func (conn *Connection) receivedCiphertextRecord(opts *Options, hdr record.Encrypted) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if err := conn.checkReceiveLimits(); err != nil {
		return err
	}
	recordBody, rn, contentType, err := conn.deprotectLocked(hdr)
	if err != nil {
		// either garbage, attack or epoch wrapping
		return err
	}
	fmt.Printf("dtls: ciphertext deprotected with rn={%d,%d} cid(hex): %x from %v, body(hex): %x\n", rn.Epoch(), rn.SeqNum(), hdr.CID, conn.addr, recordBody)
	// [rfc9147:4.1]
	switch contentType { // TODO - call StateMachine here
	case record.RecordTypeAlert:
		return conn.receivedAlertLocked(true, recordBody)
	case record.RecordTypeAck:
		// does not depend on conn.state()
		return conn.receivedEncryptedAckLocked(opts, recordBody, rn)
	case record.RecordTypeApplicationData:
		// TODO - allow or drop based on early data state
		return conn.receivedApplicationDataLocked(recordBody, rn)
	case record.RecordTypeHandshake:
		return conn.receivedEncryptedHandshakeRecordLocked(opts, recordBody, rn)
	}
	return dtlserrors.ErrUnknownInnerPlaintextRecordType
}

func (conn *Connection) receivedAlertLocked(encrypted bool, recordBody []byte) error {
	// record with an Alert type MUST contain exactly one message. [rfc8446:5.1]
	var alert record.Alert
	if err := alert.Parse(recordBody); err != nil {
		return err
	}
	if encrypted && alert.IsFatal() {
		_ = conn.ShutdownLocked(alert)
	}
	// TODO - beware of unencrypted alert!
	fmt.Printf("dtls: got alert record (encrypted=%v) fatal=%v description=%d from %v\n", encrypted, alert.IsFatal(), alert.Description, conn.addr)
	return nil
}

func (conn *Connection) receivedApplicationDataLocked(recordBody []byte, rn record.Number) error {
	fmt.Printf("dtls: got application data record (encrypted) %d bytes from %v, message: %q\n", len(recordBody), conn.addr, recordBody)
	return conn.handler.OnReadRecordLocked(rn.Epoch() == 1, recordBody)
}

func (conn *Connection) receivedEncryptedHandshakeRecordLocked(opts *Options, recordBody []byte, rn record.Number) error {
	fmt.Printf("dtls: got handshake record (encrypted) %d bytes from %v, message(hex): %x\n", len(recordBody), conn.addr, recordBody)
	if len(recordBody) == 0 {
		// [rfc8446:5.1] Implementations MUST NOT send zero-length fragments of Handshake types, even if those fragments contain padding
		return dtlserrors.ErrHandshakeRecordEmpty
	}
	messageOffset := 0
	// there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(recordBody) {
		var fragment handshake.Fragment
		n, err := fragment.Parse(recordBody[messageOffset:])
		if err != nil {
			opts.Stats.BadMessageHeader("handshake(encrypted)", messageOffset, len(recordBody), conn.addr, err)
			return dtlserrors.ErrEncryptedHandshakeMessageHeaderParsing
		}
		messageOffset += n

		switch fragment.Header.MsgType {
		case handshake.MsgTypeClientHello:
			opts.Stats.MustNotBeEncrypted("handshake(encrypted)", handshake.MsgTypeToName(fragment.Header.MsgType), conn.addr, fragment.Header)
			return dtlserrors.ErrClientHelloMustNotBeEncrypted
		case handshake.MsgTypeServerHello:
			opts.Stats.MustNotBeEncrypted("handshake(encrypted)", handshake.MsgTypeToName(fragment.Header.MsgType), conn.addr, fragment.Header)
			return dtlserrors.ErrServerHelloMustNotBeEncrypted
		}
		err = conn.state().OnHandshakeMsgFragment(conn, opts, fragment, rn)
		if dtlserrors.IsFatal(err) { // manual check in the loop, otherwise simply return
			return err
		} else if err != nil {
			opts.Stats.Warning(conn.addr, err)
		}
	}
	return nil
}

func (conn *Connection) receivedNewSessionTicket(opts *Options, fragment handshake.Fragment, rn record.Number) error {
	if conn.nextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.keys.AddAck(rn)
	conn.nextMessageSeqReceive++                          // never due to check above
	fmt.Printf("received and ignored NewSessionTicket\n") // TODO
	return nil
}

func (conn *Connection) receivedKeyUpdate(opts *Options, fragment handshake.Fragment, rn record.Number) error {
	var msgKeyUpdate handshake.MsgKeyUpdate
	if err := msgKeyUpdate.Parse(fragment.Body); err != nil {
		return dtlserrors.ErrKeyUpdateMessageParsing
	}
	fmt.Printf("KeyUpdate parsed: %+v\n", msgKeyUpdate)
	if conn.hctx != nil {
		opts.Stats.Warning(conn.addr, dtlserrors.ErrPostHandshakeMessageDuringHandshake)
		return nil
	}
	if conn.nextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.keys.AddAck(rn)
	conn.nextMessageSeqReceive++ // never due to check above
	fmt.Printf("received KeyUpdate (%+v), expecting to receive record with the next epoch\n", msgKeyUpdate)
	conn.removeOldReceiveKeys()
	if err := conn.generateNewReceiveKeys(); err != nil {
		return err
	}
	if msgKeyUpdate.UpdateRequested {
		if err := conn.keyUpdateStart(false); err != nil { // do not request update, when responding to request
			return err
		}
	}
	return nil
}

func (conn *Connection) removeOldReceiveKeys() {
	if conn.keys.NewReceiveKeysSet {
		// Move keys from "new" slot to "current" slot.
		conn.keys.NewReceiveKeysSet = false

		// do not free memory, suite will update NewReceiveSymmetric in place next time
		conn.keys.ReceiveSymmetric, conn.keys.NewReceiveSymmetric =
			conn.keys.NewReceiveSymmetric, conn.keys.ReceiveSymmetric
		conn.keys.ReceiveNextSeq, conn.keys.NewReceiveNextSeq =
			conn.keys.NewReceiveNextSeq, replay.Window{}
		conn.keys.FailedDeprotection, conn.keys.NewReceiveFailedDeprotection =
			conn.keys.NewReceiveFailedDeprotection, 0
		conn.debugPrintKeys()
	}
}

func (conn *Connection) generateNewReceiveKeys() error {
	if conn.keys.ReceiveEpoch == math.MaxUint16 {
		return dtlserrors.ErrUpdatingKeysWouldOverflowEpoch
	}
	if conn.keys.NewReceiveKeysSet {
		panic("cannot generate new keys more than once, we must first remove old set")
	}
	conn.keys.NewReceiveKeysSet = true
	conn.keys.ReceiveEpoch++
	conn.keys.NewReceiveSymmetric = conn.keys.Suite().ResetSymmetricKeys(conn.keys.NewReceiveSymmetric, conn.keys.ReceiveApplicationTrafficSecret)
	conn.keys.ReceiveApplicationTrafficSecret = keys.ComputeNextApplicationTrafficSecret(conn.keys.Suite(), "receive", conn.keys.ReceiveApplicationTrafficSecret)
	conn.debugPrintKeys()
	return nil
}
