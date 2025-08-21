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

func (conn *ConnectionImpl) ReceivedCiphertextRecord(opts *options.TransportOptions, hdr record.Ciphertext) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if err := conn.checkReceiveLimits(); err != nil {
		return err
	}
	decrypted, rn, contentType, err := conn.deprotectLocked(hdr)
	if err != nil {
		// either garbage, attack or epoch wrapping
		return err
	}
	log.Printf("dtls: ciphertext deprotected with rn={%d,%d} cid(hex): %x from %v, body(hex): %x", rn.Epoch(), rn.SeqNum(), hdr.CID, conn.addr, decrypted)
	// [rfc9147:4.1]
	switch contentType { // TODO - call StateMachine here
	case record.RecordTypeAlert:
		return conn.ReceivedAlert(true, decrypted)
	case record.RecordTypeAck:
		return conn.receivedEncryptedAck(opts, decrypted)
	case record.RecordApplicationData:
		return conn.receivedApplicationData(decrypted)
	case record.RecordTypeHandshake:
		return conn.receivedEncryptedHandshakeRecord(opts, decrypted, rn)
	}
	return dtlserrors.ErrUnknownInnerPlaintextRecordType
}

func (conn *ConnectionImpl) ReceivedAlert(encrypted bool, messageData []byte) error {
	// TODO - beware of unencrypted alert!
	log.Printf("dtls: got alert record (encrypted=%v) %d bytes from %v, message(hex): %x", encrypted, len(messageData), conn.addr, messageData)
	// messageData must be 2 bytes, TODO - parse and process alert
	// record with an Alert type MUST contain exactly one message. [rfc8446:5.1]
	return nil
}

func (conn *ConnectionImpl) receivedApplicationData(messageData []byte) error {
	log.Printf("dtls: got application data record (encrypted) %d bytes from %v, message: %q", len(messageData), conn.addr, messageData)
	if conn.roleServer && conn.Handler != nil {
		// TODO - controller to play with state. Remove after testing!
		if strings.HasPrefix(string(messageData), "upds") && conn.sendKeyUpdateMessageSeq == 0 {
			if err := conn.startKeyUpdate(false); err != nil {
				return err
			}
		}
		if strings.HasPrefix(string(messageData), "upd2") && conn.sendKeyUpdateMessageSeq == 0 {
			if err := conn.startKeyUpdate(true); err != nil {
				return err
			}
		}
		if ha, ok := conn.Handler.(*exampleHandler); ok {
			ha.toSend = string(messageData)
			conn.handlerHasMoreData = true
		}
	}
	return nil
}

// TODO - replace this func with call to state machine
func (conn *ConnectionImpl) receivedEncryptedHandshakeRecord(opts *options.TransportOptions, recordData []byte, rn record.Number) error {
	log.Printf("dtls: got handshake record (encrypted) %d bytes from %v, message(hex): %x", len(recordData), conn.addr, recordData)
	if len(recordData) == 0 {
		// [rfc8446:5.1] Implementations MUST NOT send zero-length fragments of Handshake types, even if those fragments contain padding
		return dtlserrors.ErrHandshakeRecordEmpty
	}
	messageOffset := 0
	// there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(recordData) {
		var fragment handshake.Fragment
		n, err := fragment.Parse(recordData[messageOffset:])
		if err != nil {
			opts.Stats.BadMessageHeader("handshake(encrypted)", messageOffset, len(recordData), conn.addr, err)
			return dtlserrors.ErrEncryptedHandshakeMessageHeaderParsing
		}
		messageOffset += n

		if fragment.Header.MsgSeq < conn.firstMessageSeqInReceiveQueue() {
			// all messages before were processed by us in the state we already do not remember,
			// so we must acknowledge unconditionally and do nothing.
			conn.keys.AddAck(rn)
			continue
		}
		switch fragment.Header.MsgType {
		case handshake.MsgTypeClientHello:
			opts.Stats.MustNotBeEncrypted("handshake(encrypted)", handshake.MsgTypeToName(fragment.Header.MsgType), conn.addr, fragment.Header)
			return dtlserrors.ErrClientHelloMustNotBeEncrypted
		case handshake.MsgTypeServerHello:
			opts.Stats.MustNotBeEncrypted("handshake(encrypted)", handshake.MsgTypeToName(fragment.Header.MsgType), conn.addr, fragment.Header)
			return dtlserrors.ErrServerHelloMustNotBeEncrypted
		case handshake.MsgTypeNewSessionTicket:
			if err := conn.receivedNewSessionTicket(opts, fragment, rn); err != nil {
				return err
			}
		case handshake.MsgTypeKeyUpdate:
			if err := conn.receivedKeyUpdate(opts, fragment, rn); err != nil {
				return err
			}
		default:
			if conn.hctx == nil {
				opts.Stats.Warning(conn.addr, dtlserrors.ErrHandshakeMessagePostHandshake)
				continue
			}
			// we must never add post-handshake messages to received messages queue in Handshake,
			// because we could partially acknowledge them, so later when we need to destroy conn.Handshake,
			// we will not be able to throw them out (peer will never send fragments again), and we will not
			// be able to process them immediately.
			// So all post-handshake messages muet be processed in switch statement above.
			if err := conn.hctx.ReceivedFragment(conn, fragment, rn); err != nil {
				return err
			}
		}
	}
	return nil
}

func (conn *ConnectionImpl) receivedNewSessionTicket(opts *options.TransportOptions, fragment handshake.Fragment, rn record.Number) error {
	if conn.nextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.keys.AddAck(rn)
	conn.nextMessageSeqReceive++                        // never due to check above
	log.Printf("received and ignored NewSessionTicket") // TODO
	return nil
}

func (conn *ConnectionImpl) receivedKeyUpdate(opts *options.TransportOptions, fragment handshake.Fragment, rn record.Number) error {
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
		if err := conn.startKeyUpdate(false); err != nil { // do not request update, when responding to request
			return err
		}
	}
	return nil
}
