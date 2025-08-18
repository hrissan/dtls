package handshake

import (
	"errors"
	"log"
	"math"
	"net/netip"
	"slices"
	"sync"

	"github.com/hrissan/tinydtls/constants"
	"github.com/hrissan/tinydtls/dtlserrors"
	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
	"github.com/hrissan/tinydtls/transport/options"
)

type ConnectionHandler interface {
	// application must remove connection from all data structures
	// connection will be reused and become invalid immediately after method returns
	OnDisconnect(err error)

	// if connection was register for send with transport, this method will be called
	// in the near future. record is allocated and resized to maximum size application
	// is allowed to write.
	// Application sets send = true, if it filled record. recordSize is # of bytes filled
	// (recordSize can be 0 to send 0-size record, if recordSize > len(record), then panic)
	// Application sets moreData if it still has more data to send.
	// Application can set send = false, and moreData = true only in case it did not want
	// to send short record (application may prefer to send longer record on the next call).
	OnWriteApplicationRecord(record []byte) (recordSize int, send bool, moreData bool)

	// every record sent will be delivered as is. Sent empty records are delivered as empty records.
	// record points to buffer inside transport and must not be retained.
	// bytes are guaranteed to be valid only during the call.
	// if application returns error, connection close will be initiated, expect OnDisconnect in the near future.
	OnReadApplicationRecord(record []byte) error
}

// Contains absolute minimum of what's mandatory for after handshake finished
// keys, record replay buffer, ack queue for KeyUpdate and NewSessionTicket messages
// all other information is in HandshakeContext structure and will be reused
// after handshake finish
type ConnectionImpl struct {
	// variables below mu are protected by mu, except where noted
	mu   sync.Mutex     // TODO - check that mutex is alwasy taken
	Addr netip.AddrPort // changes very rarely
	Keys keys.Keys

	// we do not support those messages to be fragmented, because we do not want
	// to allocate memory for reassembly
	ackKeyUpdate           format.RecordNumber // if != 0, send ack
	ackKeyNewSessionTicket format.RecordNumber // if != 0, send ack
	sendKeyUpdateRN        format.RecordNumber // if != 0, already sent, on resend overwrite rn
	sendNewSessionTicketRN format.RecordNumber // if != 0, already sent, on resend overwrite rn

	Handshake            *HandshakeConnection // content is also protected by mutex above
	Handler              ConnectionHandler
	HandlerHasMoreData   bool // set when user signals it has data, clears after OnWriteRecord returns false
	RoleServer           bool // changes very rarely
	sendKeyUpdate        bool
	sendNewSessionTicket bool

	InSenderQueue    bool  // intrusive, must not be changed except by sender, protected by sender mutex
	TimerHeapIndex   int   // intrusive, must not be changed except by clock, protected by clock mutex
	FireTimeUnixNano int64 // time.Time object is larger and might be invalid as a heap predicate
}

func (conn *ConnectionImpl) HasDataToSend() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.hasDataToSendLocked()
}

func (conn *ConnectionImpl) hasDataToSendLocked() bool {
	hctx := conn.Handshake
	if hctx != nil && hctx.SendQueue.HasDataToSend() {
		return true
	}
	if hctx != nil && hctx.sendAcks.HasDataToSend(conn) {
		return true
	}
	return conn.HandlerHasMoreData ||
		conn.ackKeyUpdate != (format.RecordNumber{}) ||
		conn.ackKeyNewSessionTicket != (format.RecordNumber{})
}

// must not write over len(datagram), returns part of datagram filled
func (conn *ConnectionImpl) ConstructDatagram(datagram []byte) (datagramSize int, addToSendQueue bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	hctx := conn.Handshake
	if hctx != nil {
		// we decided to first send our messages, then acks.
		// because message has a chance to ack the whole flight
		datagramSize += hctx.SendQueue.ConstructDatagram(conn, datagram[datagramSize:])
		datagramSize += hctx.sendAcks.ConstructDatagram(conn, datagram[datagramSize:])
	}
	sendAcks := make([]format.RecordNumber, 0, 2) // probably on stack
	if conn.ackKeyUpdate != (format.RecordNumber{}) {
		sendAcks = append(sendAcks, conn.ackKeyUpdate)
	}
	if conn.ackKeyNewSessionTicket != (format.RecordNumber{}) {
		sendAcks = append(sendAcks, conn.ackKeyNewSessionTicket)
	}
	acksSpace := len(datagram) - datagramSize - format.MessageAckHeaderSize - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
	if len(sendAcks) != 0 && acksSpace >= 2*format.MessageAckRecordNumberSize {
		slices.SortFunc(sendAcks, format.RecordNumberCmp)
		da := conn.constructCiphertextAck(datagram[datagramSize:datagramSize], sendAcks)
		if len(da) > len(datagram[datagramSize:]) {
			panic("ciphertext ack record construction length invariant failed")
		}
		datagramSize += len(da)
		conn.ackKeyUpdate = format.RecordNumber{}
		conn.ackKeyNewSessionTicket = format.RecordNumber{}
	}
	if conn.Handler != nil { // application data
		// If we remove "if" below, we put ack for client_hello together with
		// application data into the same datagram. Then wolfSSL_connect will return
		// err = -441, Application data is available for reading
		// TODO: contact WolfSSL team
		if datagramSize > 0 {
			return datagramSize, true
		}
		userSpace := len(datagram) - datagramSize - 1 - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
		if userSpace >= constants.MinFragmentBodySize {
			record := datagram[datagramSize+format.OutgoingCiphertextRecordHeader : datagramSize+format.OutgoingCiphertextRecordHeader+userSpace]
			recordSize, send, add := conn.Handler.OnWriteApplicationRecord(record)
			if recordSize > len(record) {
				panic("ciphertext user handler overflows allowed record")
			}
			if send {
				da := conn.constructCiphertextApplication(datagram[datagramSize : datagramSize+format.OutgoingCiphertextRecordHeader+recordSize])
				if len(da) > len(datagram[datagramSize:]) {
					panic("ciphertext application record construction length invariant failed")
				}
				datagramSize += len(da)
			}
			if !add {
				conn.HandlerHasMoreData = false
			}
		}
	}
	return datagramSize, conn.hasDataToSendLocked()
}

var ErrUpdatingKeysWouldOverflowEpoch = errors.New("updating keys would overflow epoch")
var ErrNewSessionTicketFragmented = errors.New("fragmented NewSessionTicket message not supported")

func (conn *ConnectionImpl) receivedNewSessionTicket(opts *options.TransportOptions, handshakeHdr format.MessageHandshakeHeader, body []byte, rn format.RecordNumber) error {
	if handshakeHdr.IsFragmented() {
		// we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		opts.Stats.Warning(conn.Addr, dtlserrors.WarnNewSessionTicketFragmented)
		return nil
	}
	if conn.Handshake != nil {
		opts.Stats.Warning(conn.Addr, dtlserrors.ErrPostHandshakeMessageDuringHandshake)
		return nil
	}
	if handshakeHdr.MessageSeq > conn.Keys.NextMessageSeqReceive {
		return nil // totally ok to ignore
	}
	if conn.ackKeyNewSessionTicket == (format.RecordNumber{}) {
		conn.ackKeyNewSessionTicket = rn
	}
	if handshakeHdr.MessageSeq != conn.Keys.NextMessageSeqReceive {
		return nil // totally ok to ignore
	}
	conn.Keys.NextMessageSeqReceive++
	log.Printf("received and ignored NewSessionTicket") // TODO
	return nil
}

func (conn *ConnectionImpl) receivedKeyUpdate(opts *options.TransportOptions, handshakeHdr format.MessageHandshakeHeader, body []byte, rn format.RecordNumber) error {
	if handshakeHdr.IsFragmented() {
		// alert - we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		opts.Stats.Warning(conn.Addr, dtlserrors.WarnKeyUpdateFragmented)
		return nil
	}
	if conn.Handshake != nil {
		opts.Stats.Warning(conn.Addr, dtlserrors.ErrPostHandshakeMessageDuringHandshake)
		return nil
	}
	if handshakeHdr.MessageSeq > conn.Keys.NextMessageSeqReceive {
		return nil // totally ok to ignore
	}
	if conn.ackKeyUpdate == (format.RecordNumber{}) {
		conn.ackKeyUpdate = rn
	}
	if handshakeHdr.MessageSeq != conn.Keys.NextMessageSeqReceive {
		return nil // totally ok to ignore
	}
	conn.Keys.NextMessageSeqReceive++
	log.Printf("received and ignored KeyUpdate") // TODO
	return nil
}

func (conn *ConnectionImpl) deprotectLocked(hdr format.CiphertextRecordHeader, seqNumData []byte, header []byte, body []byte) (decrypted []byte, rn format.RecordNumber, contentType byte, err error) {
	receiver := &conn.Keys.Receive
	var seq uint64
	if hdr.MatchesEpoch(receiver.Symmetric.Epoch) {
		nextSeq := conn.Keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
		decrypted, seq, contentType, err = receiver.Symmetric.Deprotect(hdr, !conn.Keys.DoNotEncryptSequenceNumbers, nextSeq,
			seqNumData, header, body)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			conn.Keys.FailedDeprotectionCounter++
			return
		}
		if !conn.Keys.ReceiveNextSegmentSequence.SetReceivedIsUnique(seq + 1) {
			return // replay protection
		}
	} else {
		// We should check here that receiver.Epoch+1 does not overflow, because we increment it below
		if !conn.Keys.ExpectEpochUpdate || receiver.Symmetric.Epoch == math.MaxUint16 || !hdr.MatchesEpoch(receiver.Symmetric.Epoch+1) {
			err = ErrUpdatingKeysWouldOverflowEpoch
			return
		}
		// We should not believe new epoch bits before we decrypt record successfully,
		// so we have to calculate new keys here. But if we fail decryption, then we
		// either should store new keys, or recompute them on each (attacker's) packet.
		// So, we decided we better store new keys
		if !conn.Keys.NewReceiveKeysSet {
			conn.Keys.NewReceiveKeysSet = true
			conn.Keys.NewReceiveKeys.Epoch = receiver.Symmetric.Epoch + 1
			conn.Keys.NewReceiveKeys.ComputeKeys(receiver.ApplicationTrafficSecret[:]) // next application traffic secret is calculated from the previous one
			conn.Keys.NewReceiveKeysFailedDeprotectionCounter = 0
		}
		decrypted, seq, contentType, err = conn.Keys.NewReceiveKeys.Deprotect(hdr, !conn.Keys.DoNotEncryptSequenceNumbers, 0,
			seqNumData, header, body)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			conn.Keys.NewReceiveKeysFailedDeprotectionCounter++
			return
		}
		conn.Keys.ExpectEpochUpdate = false
		receiver.Symmetric = conn.Keys.NewReceiveKeys // epoch is also copied
		conn.Keys.ReceiveNextSegmentSequence.Reset()
		_ = conn.Keys.ReceiveNextSegmentSequence.SetReceivedIsUnique(seq + 1) // always unique
		conn.Keys.FailedDeprotectionCounter = conn.Keys.NewReceiveKeysFailedDeprotectionCounter
		conn.Keys.NewReceiveKeys = keys.SymmetricKeys{} // remove alias
		conn.Keys.NewReceiveKeysSet = false
		conn.Keys.NewReceiveKeysFailedDeprotectionCounter = 0
	}
	rn = format.RecordNumberWith(receiver.Symmetric.Epoch, seq)
	return
}

func (conn *ConnectionImpl) ProcessCiphertextRecord(opts *options.TransportOptions, hdr format.CiphertextRecordHeader, cid []byte, seqNumData []byte, header []byte, body []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	decrypted, rn, contentType, err := conn.deprotectLocked(hdr, seqNumData, header, body)
	if err != nil { // TODO - deprotectLocked should return dtlserror.Error
		opts.Stats.Warning(conn.Addr, dtlserrors.WarnFailedToDeprotectRecord)
		// either garbage, attack or epoch wrapping
		return nil
	}
	log.Printf("dtls: ciphertext %v deprotected with rn=%v cid(hex): %x from %v, body(hex): %x", hdr, rn, cid, conn.Addr, decrypted)
	if !format.IsInnerPlaintextRecord(contentType) {
		// warning instead of error here is debatable, probably some DTLSv1.2 message from mixed implementation
		opts.Stats.Warning(conn.Addr, dtlserrors.WarnUnknownInnerPlaintextRecordType)
		return nil
	}
	messageOffset := 0 // there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(decrypted) {
		messageData := decrypted[messageOffset:]
		switch contentType {
		case format.PlaintextContentTypeAlert:
			log.Printf("dtls: got alert(encrypted) %v from %v, message(hex): %x", hdr, conn.Addr, messageData)
			// messageData must be 2 bytes, TODO - parse and process alert
			// record with an Alert type MUST contain exactly one message. [rfc8446:5.1]
			return nil
		case format.PlaintextContentTypeHandshake:
			log.Printf("dtls: got handshake(encrypted) %v from %v, message(hex): %x", hdr, conn.Addr, messageData)
			var handshakeHdr format.MessageHandshakeHeader
			n, body, err := handshakeHdr.ParseWithBody(messageData)
			if err != nil {
				opts.Stats.BadMessageHeader("handshake(encrypted)", messageOffset, len(decrypted), conn.Addr, err)
				return dtlserrors.ErrEncryptedHandshakeMessageHeaderParsing
			}
			messageData = messageData[:n]
			messageOffset += n
			switch handshakeHdr.HandshakeType {
			case format.HandshakeTypeClientHello:
				opts.Stats.MustNotBeEncrypted("handshake(encrypted)", format.HandshakeTypeToName(handshakeHdr.HandshakeType), conn.Addr, handshakeHdr)
				return dtlserrors.ErrClientHelloMustNotBeEncrypted
			case format.HandshakeTypeServerHello:
				opts.Stats.MustNotBeEncrypted("handshake(encrypted)", format.HandshakeTypeToName(handshakeHdr.HandshakeType), conn.Addr, handshakeHdr)
				return dtlserrors.ErrServerHelloMustNotBeEncrypted
			case format.HandshakeTypeNewSessionTicket:
				if err := conn.receivedNewSessionTicket(opts, handshakeHdr, body, rn); err != nil {
					return err
				}
			case format.HandshakeTypeKeyUpdate:
				if err := conn.receivedKeyUpdate(opts, handshakeHdr, body, rn); err != nil {
					return err
				}
			default:
				if conn.Handshake != nil {
					flight := HandshakeTypeToFlight(handshakeHdr.HandshakeType, conn.RoleServer) // zero if unknown
					conn.Handshake.ReceivedFlight(conn, flight)
					// receiving any chunk from the next flight will remove all acks for previous flights
					// before this and subsequent chunks are added to hctx.acks
					if err := conn.Handshake.ReceivedMessage(conn, handshakeHdr, body, rn); err != nil {
						return err
					}
				}
			}
		case format.PlaintextContentTypeAck:
			var insideBody []byte
			if insideBody, err = format.ParseMessageAcks(messageData); err != nil {
				return dtlserrors.ErrEncryptedAckMessageHeaderParsing
			}
			conn.ReceiveAcks(opts, insideBody)
			log.Printf("dtls: got ack(encrypted) %v from %v, message(hex): %x", hdr, conn.Addr, messageData)
			// if all messages from epoch 2 acked, then switch sending epoch
			if conn.Handshake != nil && conn.Handshake.SendQueue.Len() == 0 && conn.Keys.Send.Symmetric.Epoch == 2 {
				conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
				conn.Keys.Send.Symmetric.Epoch++
				conn.Keys.SendNextSegmentSequence = 0
				conn.Handshake = nil // TODO - reuse into pool
				conn.Handler = &exampleHandler{toSend: "Hello from client\n"}
				conn.HandlerHasMoreData = true
			}
			return nil // ack occupies full record
		case format.PlaintextContentTypeApplicationData:
			log.Printf("dtls: got application_data(encrypted) %v from %v, message: %q", hdr, conn.Addr, messageData)
			return nil // application data occupies full record
		default:
			panic("content type checked in format.IsPlaintextRecord()")
		}
	}
	return nil // TODO - we allow empty records of handshake type, must fix
}

func (conn *ConnectionImpl) OnTimer() {
}

type exampleHandler struct {
	toSend string
}

func (h *exampleHandler) OnDisconnect(err error) {

}

func (h *exampleHandler) OnWriteApplicationRecord(record []byte) (recordSize int, send bool, addToSendQueue bool) {
	toSend := copy(record, h.toSend)
	h.toSend = h.toSend[toSend:]
	return toSend, toSend != 0, len(h.toSend) > 0
}

func (h *exampleHandler) OnReadApplicationRecord(record []byte) error {
	return nil
}
