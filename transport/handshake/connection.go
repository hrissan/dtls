package handshake

import (
	"errors"
	"log"
	"math"
	"net/netip"
	"slices"
	"sync"

	"github.com/hrissan/tinydtls/constants"
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
	// There is 3 possible outcomes
	// 1. Application already has nothing to send,
	//    should return <anything>, false, false
	// 2. Application filled record, and now has nothing to send
	//    should return recordSize, true, false. recordSize can be 0, then empty record will be sent.
	// 3. Application filled record, but still has more data to send, which did not fit
	//    should return recordSize, true, true. recordSize can be 0, empty record will be sent
	// returning recordSize > len(record) || send = false, addToSendQueue = true is immediate panic (API violation)
	OnWriteApplicationRecord(record []byte) (recordSize int, send bool, addToSendQueue bool)

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
	RoleServer           bool // changes very rarely
	sendKeyUpdate        bool
	sendNewSessionTicket bool

	InSenderQueue    bool  // intrusive, must not be changed except by sender, protected by sender mutex
	TimerHeapIndex   int   // intrusive, must not be changed except by clock, protected by clock mutex
	FireTimeUnixNano int64 // time.Time object is larger and might be invalid as a heap predicate
}

// must not write over len(datagram), returns part of datagram filled
func (conn *ConnectionImpl) ConstructDatagram(datagram []byte) (datagramSize int, addToSendQueue bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.Handshake != nil {
		datagramSize, addToSendQueue = conn.Handshake.ConstructDatagram(conn, datagram)
		// If we remove "if" below, we put ack for client_hello together with
		// application data into the same datagram. Then wolfSSL_connect will return
		// err = -441, Application data is available for reading
		// TODO: contact WolfSSL team
		if datagramSize > 0 {
			return datagramSize, true
		}
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
	// TODO - application data
	if conn.Handler != nil {
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
				addToSendQueue = addToSendQueue || add
			}
		}
	}
	return
}

var ErrUpdatingKeysWouldOverflowEpoch = errors.New("updating keys would overflow epoch")

func (conn *ConnectionImpl) receivedNewSessionTicket(handshakeHdr format.MessageHandshakeHeader, body []byte, rn format.RecordNumber) (registerInSender bool) {
	if handshakeHdr.IsFragmented() {
		// alert - we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		return
	}
	if conn.Handshake != nil {
		return // alert - post-handshake message prohibited during handshake
	}
	if handshakeHdr.MessageSeq > conn.Keys.NextMessageSeqReceive {
		return // totally ok to ignore
	}
	if conn.ackKeyNewSessionTicket == (format.RecordNumber{}) {
		conn.ackKeyNewSessionTicket = rn
		registerInSender = true
	}
	if handshakeHdr.MessageSeq != conn.Keys.NextMessageSeqReceive {
		return // totally ok to ignore
	}
	conn.Keys.NextMessageSeqReceive++
	log.Printf("received and ignored NewSessionTicket") // TODO
	return
}

func (conn *ConnectionImpl) receivedKeyUpdate(handshakeHdr format.MessageHandshakeHeader, body []byte, rn format.RecordNumber) (registerInSender bool) {
	if handshakeHdr.IsFragmented() {
		// alert - we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		return
	}
	if conn.Handshake != nil {
		return // alert - post-handshake message prohibited during handshake
	}
	if handshakeHdr.MessageSeq > conn.Keys.NextMessageSeqReceive {
		return // totally ok to ignore
	}
	if conn.ackKeyUpdate == (format.RecordNumber{}) {
		conn.ackKeyUpdate = rn
		registerInSender = true
	}
	if handshakeHdr.MessageSeq != conn.Keys.NextMessageSeqReceive {
		return // totally ok to ignore
	}
	conn.Keys.NextMessageSeqReceive++
	log.Printf("received and ignored KeyUpdate") // TODO
	return
}

func (conn *ConnectionImpl) deprotectLocked(hdr format.CiphertextRecordHeader, seqNumData []byte, header []byte, body []byte) (decrypted []byte, rn format.RecordNumber, contentType byte, err error) {
	receiver := &conn.Keys.Receive
	var seq uint64
	if hdr.MatchesEpoch(receiver.Symmetric.Epoch) {
		decrypted, seq, contentType, err = receiver.Symmetric.Deprotect(hdr, !conn.Keys.DoNotEncryptSequenceNumbers, conn.Keys.Receive.NextSegmentSequence,
			seqNumData, header, body)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			conn.Keys.FailedDeprotectionCounter++
			return
		}
		conn.Keys.Receive.NextSegmentSequence = seq + 1 // TODO - update replay window
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
		receiver.NextSegmentSequence = seq + 1        // TODO - update replay window
		conn.Keys.FailedDeprotectionCounter = conn.Keys.NewReceiveKeysFailedDeprotectionCounter
		conn.Keys.NewReceiveKeys = keys.SymmetricKeys{} // remove alias
		conn.Keys.NewReceiveKeysSet = false
		conn.Keys.NewReceiveKeysFailedDeprotectionCounter = 0
	}
	rn = format.RecordNumberWith(receiver.Symmetric.Epoch, seq)
	return
}

func (conn *ConnectionImpl) ProcessCiphertextRecord(opts *options.TransportOptions, hdr format.CiphertextRecordHeader, cid []byte, seqNumData []byte, header []byte, body []byte, addr netip.AddrPort) (registerInSender bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	decrypted, rn, contentType, err := conn.deprotectLocked(hdr, seqNumData, header, body)
	if err != nil {
		// TODO - alert, either garbage, attack or epoch wrapping
		return
	}
	log.Printf("dtls: ciphertext %v deprotected with rn=%v cid(hex): %x from %v, body(hex): %x", hdr, rn, cid, addr, decrypted)
	if !format.IsInnerPlaintextRecord(contentType) {
		// TODO - send alert
		return
	}
	messageOffset := 0 // there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(decrypted) {
		messageData := decrypted[messageOffset:]
		switch contentType {
		case format.PlaintextContentTypeAlert:
			log.Printf("dtls: got alert(encrypted) %v from %v, message(hex): %x", hdr, addr, messageData)
			return // TODO - more checks
		case format.PlaintextContentTypeHandshake:
			log.Printf("dtls: got handshake(encrypted) %v from %v, message(hex): %x", hdr, addr, messageData)
			var handshakeHdr format.MessageHandshakeHeader
			n, body, err := handshakeHdr.ParseWithBody(messageData)
			if err != nil {
				opts.Stats.BadMessageHeader("handshake(encrypted)", messageOffset, len(decrypted), addr, err)
				// TODO: alert here, and we cannot continue to the next record.
				return
			}
			messageData = messageData[:n]
			messageOffset += n
			if handshakeHdr.HandshakeType == format.HandshakeTypeClientHello || handshakeHdr.HandshakeType == format.HandshakeTypeServerHello {
				opts.Stats.MustNotBeEncrypted("handshake(encrypted)", format.HandshakeTypeToName(handshakeHdr.HandshakeType), addr, handshakeHdr)
				// TODO: alert here, and we do not want to continue to the next record.
				return
			}
			switch handshakeHdr.HandshakeType {
			case format.HandshakeTypeNewSessionTicket:
				registerInSender = conn.receivedNewSessionTicket(handshakeHdr, body, rn)
				continue
			case format.HandshakeTypeKeyUpdate:
				registerInSender = conn.receivedKeyUpdate(handshakeHdr, body, rn)
				continue
			}
			if conn.Handshake != nil {
				flight := HandshakeTypeToFlight(handshakeHdr.HandshakeType, conn.RoleServer) // zero if unknown
				conn.Handshake.ReceivedFlight(conn, flight)
				// receiving any chunk from the next flight will remove all acks for previous flights
				// before this and subsequent chunks are added to hctx.acks
				registerInSender = conn.Handshake.ReceivedMessage(conn, handshakeHdr, body, rn) || registerInSender
			}
		case format.PlaintextContentTypeAck:
			var insideBody []byte
			if insideBody, err = format.ParseMessageAcks(messageData); err != nil {
				log.Printf("tinydtls: failed to parse ack header: %v", err)
				return
			}
			registerInSender = conn.ReceiveAcks(insideBody)

			log.Printf("dtls: got ack(encrypted) %v from %v, message(hex): %x", hdr, addr, messageData)
			// if all messages from epoch 2 acked, then switch sending epoch
			if conn.Handshake != nil && conn.Handshake.SendQueue.Len() == 0 && conn.Keys.Send.Symmetric.Epoch == 2 {
				conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
				conn.Keys.Send.Symmetric.Epoch++
				conn.Keys.Send.NextSegmentSequence = 0
				conn.Handshake = nil // TODO - reuse into pool
				conn.Handler = &exampleHandler{toSend: "Hello from client\n"}
				registerInSender = true
			}
			return // TODO - more checks
		case format.PlaintextContentTypeApplicationData:
			log.Printf("dtls: got application_data(encrypted) %v from %v, message: %q", hdr, addr, messageData)
			//if conn.Handshake != nil { // TODO - remove
			//	conn.Handler = &exampleHandler{toSend: "tinydtls hears you: " + string(messageData)}
			//	registerInSender = true
			//}
			return // TODO - more checks
		default: // never, because checked in format.IsPlaintextRecord()
			panic("unknown content type")
		}
	}
	return
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
