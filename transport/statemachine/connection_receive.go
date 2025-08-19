package statemachine

import (
	"log"
	"math"
	"strings"

	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/handshake"
	"github.com/hrissan/tinydtls/record"
	"github.com/hrissan/tinydtls/transport/options"
)

func (conn *ConnectionImpl) ProcessCiphertextRecord(opts *options.TransportOptions, hdr record.CiphertextHeader, cid []byte, seqNumData []byte, header []byte, body []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if err := conn.checkReceiveLimits(); err != nil {
		return err
	}
	decrypted, rn, contentType, err := conn.deprotectLocked(hdr, seqNumData, header, body)
	if err != nil { // TODO - deprotectLocked should return dtlserror.Error
		opts.Stats.Warning(conn.Addr, dtlserrors.WarnFailedToDeprotectRecord)
		// either garbage, attack or epoch wrapping
		return nil
	}
	log.Printf("dtls: ciphertext %v deprotected with rn={%d,%d} cid(hex): %x from %v, body(hex): %x", hdr, rn.Epoch(), rn.SeqNum(), cid, conn.Addr, decrypted)
	// [rfc9147:4.1]
	switch contentType {
	case record.PlaintextContentTypeAlert:
		return conn.ProcessAlert(true, decrypted)
	case record.PlaintextContentTypeAck:
		return conn.ProcessEncryptedAck(opts, decrypted)
	case record.PlaintextContentTypeApplicationData:
		return conn.ProcessApplicationData(decrypted)
	case record.PlaintextContentTypeHandshake:
		return conn.ProcessEncryptedHandshakeRecord(opts, decrypted, rn)
	}
	return dtlserrors.ErrUnknownInnerPlaintextRecordType
}

func (conn *ConnectionImpl) ProcessAlert(encrypted bool, messageData []byte) error {
	// TODO - beware of unencrypted alert!
	log.Printf("dtls: got alert record (encrypted=%v) %d bytes from %v, message(hex): %x", encrypted, len(messageData), conn.Addr, messageData)
	// messageData must be 2 bytes, TODO - parse and process alert
	// record with an Alert type MUST contain exactly one message. [rfc8446:5.1]
	return nil
}

func (conn *ConnectionImpl) ProcessApplicationData(messageData []byte) error {
	log.Printf("dtls: got application data record (encrypted) %d bytes from %v, message: %q", len(messageData), conn.Addr, messageData)
	if conn.RoleServer && conn.Handler != nil {
		// TODO - controller to play with state. Remove!
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
			conn.HandlerHasMoreData = true
		}
	}
	return nil
}

func (conn *ConnectionImpl) ProcessEncryptedHandshakeRecord(opts *options.TransportOptions, recordData []byte, rn format.RecordNumber) error {
	log.Printf("dtls: got handshake record (encrypted) %d bytes from %v, message(hex): %x", len(recordData), conn.Addr, recordData)
	if len(recordData) == 0 {
		// [rfc8446:5.1] Implementations MUST NOT send zero-length fragments of Handshake types, even if those fragments contain padding
		return dtlserrors.ErrHandshakeReecordEmpty
	}
	messageOffset := 0 // there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(recordData) {
		var fragment handshake.Fragment
		n, err := fragment.Parse(recordData[messageOffset:])
		if err != nil {
			opts.Stats.BadMessageHeader("handshake(encrypted)", messageOffset, len(recordData), conn.Addr, err)
			return dtlserrors.ErrEncryptedHandshakeMessageHeaderParsing
		}
		messageOffset += n

		if fragment.Header.MsgSeq < conn.FirstMessageSeqInReceiveQueue() {
			// all messages before were processed by us in the state we already do not remember,
			// so we must acknowledge unconditionally and do nothing.
			conn.Keys.AddAck(rn)
			continue
		}
		switch fragment.Header.MsgType {
		case handshake.MsgTypeClientHello:
			opts.Stats.MustNotBeEncrypted("handshake(encrypted)", handshake.MsgTypeToName(fragment.Header.MsgType), conn.Addr, fragment.Header)
			return dtlserrors.ErrClientHelloMustNotBeEncrypted
		case handshake.MsgTypeServerHello:
			opts.Stats.MustNotBeEncrypted("handshake(encrypted)", handshake.MsgTypeToName(fragment.Header.MsgType), conn.Addr, fragment.Header)
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
			if conn.Handshake == nil {
				opts.Stats.Warning(conn.Addr, dtlserrors.ErrHandshakeMessagePostHandshake)
				continue
			}
			// we must never add post-handshake messages to received messages queue in Handshake,
			// because we could partially acknowledge them, so later when we need to destroy conn.Handshake,
			// we will not be able to throw them out (peer will never send fragments again), and we will not
			// be able to process them immediately.
			// So all post-handshake messages muet be processed in switch statement above.
			if err := conn.Handshake.ReceivedFragment(conn, fragment, rn); err != nil {
				return err
			}
		}
	}
	return nil
}

func (conn *ConnectionImpl) receivedNewSessionTicket(opts *options.TransportOptions, fragment handshake.Fragment, rn format.RecordNumber) error {
	if fragment.Header.IsFragmented() {
		// we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		opts.Stats.Warning(conn.Addr, dtlserrors.WarnNewSessionTicketFragmented)
		return nil
	}
	if conn.Handshake != nil {
		opts.Stats.Warning(conn.Addr, dtlserrors.ErrPostHandshakeMessageDuringHandshake)
		return nil
	}
	if fragment.Header.MsgSeq > conn.NextMessageSeqReceive {
		return nil
	}
	if conn.NextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.Keys.AddAck(rn)
	conn.NextMessageSeqReceive++                        // never due to check above
	log.Printf("received and ignored NewSessionTicket") // TODO
	return nil
}

func (conn *ConnectionImpl) receivedKeyUpdate(opts *options.TransportOptions, fragment handshake.Fragment, rn format.RecordNumber) error {
	if fragment.Header.IsFragmented() {
		// alert - we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		opts.Stats.Warning(conn.Addr, dtlserrors.WarnKeyUpdateFragmented)
		return nil
	}
	var msgKeyUpdate handshake.MsgKeyUpdate
	if err := msgKeyUpdate.Parse(fragment.Body); err != nil {
		return dtlserrors.ErrKeyUpdateMessageParsing
	}
	log.Printf("KeyUpdate parsed: %+v", msgKeyUpdate)
	if conn.Handshake != nil {
		opts.Stats.Warning(conn.Addr, dtlserrors.ErrPostHandshakeMessageDuringHandshake)
		return nil
	}
	if fragment.Header.MsgSeq > conn.NextMessageSeqReceive {
		return nil
	}
	if conn.NextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.Keys.AddAck(rn)
	conn.NextMessageSeqReceive++ // never due to check above
	log.Printf("received KeyUpdate (%+v), expecting to receive record with the next epoch", msgKeyUpdate)
	conn.Keys.ExpectReceiveEpochUpdate = true // if this leads to epoch overflow, we'll generate error later in the function which actually increments epoch
	if msgKeyUpdate.UpdateRequested {
		if err := conn.startKeyUpdate(false); err != nil { // do not request update, when responding to request
			return err
		}
	}
	return nil
}
