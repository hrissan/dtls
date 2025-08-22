// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"log"
	"math"
	"strings"

	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
	"github.com/hrissan/dtls/transport/options"
)

func (conn *Connection) ReceivedCiphertextRecord(opts *options.TransportOptions, hdr record.Ciphertext) error {
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
	log.Printf("dtls: ciphertext deprotected with rn={%d,%d} cid(hex): %x from %v, body(hex): %x", rn.Epoch(), rn.SeqNum(), hdr.CID, conn.addr, recordBody)
	// [rfc9147:4.1]
	switch contentType { // TODO - call StateMachine here
	case record.RecordTypeAlert:
		return conn.ReceivedAlert(true, recordBody)
	case record.RecordTypeAck:
		// does not depend on conn.State()
		return conn.receivedEncryptedAck(opts, recordBody)
	case record.RecordTypeApplicationData:
		// TODO - allow or drop based on early data state
		return conn.receivedApplicationData(recordBody)
	case record.RecordTypeHandshake:
		return conn.receivedEncryptedHandshakeRecord(opts, recordBody, rn)
	}
	return dtlserrors.ErrUnknownInnerPlaintextRecordType
}

func (conn *Connection) ReceivedAlert(encrypted bool, recordBody []byte) error {
	// record with an Alert type MUST contain exactly one message. [rfc8446:5.1]
	var alert record.Alert
	if err := alert.Parse(recordBody); err != nil {
		return err
	}
	// TODO - beware of unencrypted alert!
	log.Printf("dtls: got alert record (encrypted=%v) %d bytes from %v, %+v", encrypted, len(recordBody), conn.addr, alert)
	return nil
}

func (conn *Connection) receivedApplicationData(recordBody []byte) error {
	log.Printf("dtls: got application data record (encrypted) %d bytes from %v, message: %q", len(recordBody), conn.addr, recordBody)
	if conn.roleServer && conn.Handler != nil {
		// TODO - controller to play with state. Remove after testing!
		if strings.HasPrefix(string(recordBody), "upds") && !conn.keyUpdateInProgress() {
			if err := conn.keyUpdateStart(false); err != nil {
				return err
			}
		}
		if strings.HasPrefix(string(recordBody), "upd2") && !conn.keyUpdateInProgress() {
			if err := conn.keyUpdateStart(true); err != nil {
				return err
			}
		}
		if ha, ok := conn.Handler.(*exampleHandler); ok {
			ha.toSend = string(recordBody)
			conn.handlerHasMoreData = true
		}
	}
	return nil
}

func (conn *Connection) receivedEncryptedHandshakeRecord(opts *options.TransportOptions, recordBody []byte, rn record.Number) error {
	log.Printf("dtls: got handshake record (encrypted) %d bytes from %v, message(hex): %x", len(recordBody), conn.addr, recordBody)
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
		err = conn.State().OnHandshakeMsgFragment(conn, opts, fragment, rn)
		if dtlserrors.IsFatal(err) { // manual check in the loop, otherwise simply return
			return err
		} else if err != nil {
			opts.Stats.Warning(conn.addr, err)
		}
	}
	return nil
}

func (conn *Connection) receivedNewSessionTicket(opts *options.TransportOptions, fragment handshake.Fragment, rn record.Number) error {
	if conn.nextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.keys.AddAck(rn)
	conn.nextMessageSeqReceive++                        // never due to check above
	log.Printf("received and ignored NewSessionTicket") // TODO
	return nil
}

func (conn *Connection) receivedKeyUpdate(opts *options.TransportOptions, fragment handshake.Fragment, rn record.Number) error {
	var msgKeyUpdate handshake.MsgKeyUpdate
	if err := msgKeyUpdate.Parse(fragment.Body); err != nil {
		return dtlserrors.ErrKeyUpdateMessageParsing
	}
	log.Printf("KeyUpdate parsed: %+v", msgKeyUpdate)
	if conn.hctx != nil {
		opts.Stats.Warning(conn.addr, dtlserrors.ErrPostHandshakeMessageDuringHandshake)
		return nil
	}
	if conn.nextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.keys.AddAck(rn)
	conn.nextMessageSeqReceive++ // never due to check above
	log.Printf("received KeyUpdate (%+v), expecting to receive record with the next epoch", msgKeyUpdate)
	conn.keys.ExpectReceiveEpochUpdate = true // if this leads to epoch overflow, we'll generate error later in the function which actually increments epoch
	if msgKeyUpdate.UpdateRequested {
		if err := conn.keyUpdateStart(false); err != nil { // do not request update, when responding to request
			return err
		}
	}
	return nil
}
