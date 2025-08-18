package handshake

import (
	"errors"
	"log"
	"math"
	"net/netip"
	"slices"
	"strings"
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

	Handshake                      *HandshakeConnection // content is also protected by mutex above
	Handler                        ConnectionHandler
	HandlerHasMoreData             bool // set when user signals it has data, clears after OnWriteRecord returns false
	RoleServer                     bool // changes very rarely
	sendKeyUpdateUpdateRequested   bool
	sendKeyUpdateMessageSeq        uint16 // != 0 if set
	sendNewSessionTicketMessageSeq uint16 // != 0 if set

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
		(conn.sendKeyUpdateMessageSeq != 0 && (conn.sendKeyUpdateRN == format.RecordNumber{})) ||
		(conn.sendNewSessionTicketMessageSeq != 0 && (conn.sendNewSessionTicketRN == format.RecordNumber{})) ||
		conn.ackKeyUpdate != (format.RecordNumber{}) ||
		conn.ackKeyNewSessionTicket != (format.RecordNumber{})
}

// must not write over len(datagram), returns part of datagram filled
func (conn *ConnectionImpl) ConstructDatagram(datagram []byte) (datagramSize int, addToSendQueue bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	var err error
	datagramSize, addToSendQueue, err = conn.constructDatagram(datagram)
	if err != nil {
		log.Printf("TODO - close connection")
	}
	return
}

func (conn *ConnectionImpl) constructDatagram(datagram []byte) (int, bool, error) {
	var datagramSize int
	hctx := conn.Handshake
	if hctx != nil {
		// we decided to first send our messages, then acks.
		// because message has a chance to ack the whole flight
		if recordSize, err := hctx.SendQueue.ConstructDatagram(conn, datagram[datagramSize:]); err != nil {
			return 0, false, err
		} else {
			datagramSize += recordSize
		}
		if datagramSize != 0 {
			return datagramSize, true, nil
		}
		if recordSize, err := hctx.sendAcks.ConstructDatagram(conn, datagram[datagramSize:]); err != nil {
			return 0, false, err
		} else {
			datagramSize += recordSize
		}
		if datagramSize != 0 {
			return datagramSize, true, nil
		}
	}
	if conn.sendKeyUpdateMessageSeq != 0 && (conn.sendKeyUpdateRN == format.RecordNumber{}) {
		msgBody := make([]byte, 0, 1) // must be stack-allocated
		msg := format.MessageKeyUpdate{UpdateRequested: conn.sendKeyUpdateUpdateRequested}
		msgBody = msg.Write(msgBody)
		lenBody := uint32(len(msgBody))
		outgoing := OutgoingHandshakeMessage{
			Header: MessageHeaderMinimal{
				HandshakeType: format.HandshakeTypeKeyUpdate,
				MessageSeq:    conn.sendKeyUpdateMessageSeq,
			},
			Body:       msgBody,
			SendOffset: 0,
			SendEnd:    lenBody,
		}
		recordSize, fragmentInfo, rn, err := conn.constructRecord(datagram[datagramSize:],
			outgoing.Header, outgoing.Body,
			0, lenBody, nil)
		if err != nil {
			return 0, false, err
		}
		if recordSize != 0 {
			if fragmentInfo.FragmentOffset != 0 || fragmentInfo.FragmentLength != lenBody {
				panic("outgoing KeyUpdate must not be fragmented")
			}
			datagramSize += recordSize
			conn.sendKeyUpdateRN = rn
		}
		if datagramSize != 0 {
			return datagramSize, true, nil
		}
	}
	if conn.sendNewSessionTicketMessageSeq != 0 && (conn.sendNewSessionTicketRN != format.RecordNumber{}) {
		// TODO
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
		da, err := conn.constructCiphertextAck(datagram[datagramSize:datagramSize], sendAcks)
		if err != nil {
			return 0, false, err
		}
		if len(da) > len(datagram[datagramSize:]) {
			panic("ciphertext ack record construction length invariant failed")
		}
		datagramSize += len(da)
		conn.ackKeyUpdate = format.RecordNumber{}
		conn.ackKeyNewSessionTicket = format.RecordNumber{}
		if datagramSize != 0 {
			return datagramSize, true, nil
		}
	}
	if conn.Handler != nil { // application data
		// If we remove "if" below, we put ack for client finished together with
		// application data into the same datagram. Then wolfSSL_connect will return
		// err = -441, Application data is available for reading
		// TODO: contact WolfSSL team
		if datagramSize > 0 {
			return datagramSize, true, nil
		}
		userSpace := len(datagram) - datagramSize - 1 - format.MaxOutgoingCiphertextRecordOverhead - constants.AEADSealSize
		if userSpace >= constants.MinFragmentBodySize {
			record := datagram[datagramSize+format.OutgoingCiphertextRecordHeader : datagramSize+format.OutgoingCiphertextRecordHeader+userSpace]
			recordSize, send, add := conn.Handler.OnWriteApplicationRecord(record)
			if recordSize > len(record) {
				panic("ciphertext user handler overflows allowed record")
			}
			if send {
				da, err := conn.constructCiphertextApplication(datagram[datagramSize : datagramSize+format.OutgoingCiphertextRecordHeader+recordSize])
				if err != nil {
					return 0, false, err
				}
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
	return datagramSize, conn.hasDataToSendLocked(), nil
}

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
	if conn.Keys.NextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.Keys.NextMessageSeqReceive++                   // never due to check above
	log.Printf("received and ignored NewSessionTicket") // TODO
	return nil
}

func (conn *ConnectionImpl) receivedKeyUpdate(opts *options.TransportOptions, handshakeHdr format.MessageHandshakeHeader, body []byte, rn format.RecordNumber) error {
	var msg format.MessageKeyUpdate
	if err := msg.Parse(body); err != nil {
		return dtlserrors.ErrKeyUpdateMessageParsing
	}
	log.Printf("KeyUpdate parsed: %+v", msg)

	if handshakeHdr.IsFragmented() {
		// alert - we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		opts.Stats.Warning(conn.Addr, dtlserrors.WarnKeyUpdateFragmented)
		return nil
	}
	// TODO - uncomment after moving acks into connection from handshake
	//if conn.Handshake != nil {
	//	opts.Stats.Warning(conn.Addr, dtlserrors.ErrPostHandshakeMessageDuringHandshake)
	//	return nil
	//}
	if handshakeHdr.MessageSeq > conn.Keys.NextMessageSeqReceive {
		return nil // totally ok to ignore
	}
	if conn.ackKeyUpdate == (format.RecordNumber{}) {
		conn.ackKeyUpdate = rn
	}
	if handshakeHdr.MessageSeq != conn.Keys.NextMessageSeqReceive {
		return nil // totally ok to ignore
	}
	if conn.Keys.NextMessageSeqReceive == math.MaxUint16 {
		return dtlserrors.ErrReceivedMessageSeqOverflow
	}
	conn.Keys.NextMessageSeqReceive++ // never due to check above
	log.Printf("received KeyUpdate")
	conn.Keys.ExpectReceiveEpochUpdate = true // if this leads to epoch overflow, we'll generate error later in the function which actually increments epoch
	if msg.UpdateRequested {
		if err := conn.startKeyUpdate(false); err != nil { // do not request update, when responding to request
			return err
		}
	}
	return nil
}

func (conn *ConnectionImpl) startKeyUpdate(updateRequested bool) error {
	if conn.sendKeyUpdateMessageSeq != 0 {
		return nil // KeyUpdate in progress
	}
	if conn.Keys.NextMessageSeqSend == math.MaxUint16 {
		return dtlserrors.ErrSendMessageSeqOverflow
	}
	conn.sendKeyUpdateMessageSeq = conn.Keys.NextMessageSeqSend
	conn.sendKeyUpdateRN = format.RecordNumber{}
	conn.sendKeyUpdateUpdateRequested = updateRequested
	conn.Keys.NextMessageSeqSend++ // never due to check above
	log.Printf("KeyUpdate started (updateRequested=%v), messageSeq: %d", updateRequested, conn.sendKeyUpdateMessageSeq)
	return nil
}

func (conn *ConnectionImpl) processKeyUpdateAck(rn format.RecordNumber) {
	if conn.sendKeyUpdateMessageSeq != 0 && conn.sendKeyUpdateRN == (format.RecordNumber{}) || conn.sendKeyUpdateRN != rn {
		return
	}
	log.Printf("KeyUpdate ack received")
	conn.sendKeyUpdateMessageSeq = 0
	conn.sendKeyUpdateRN = format.RecordNumber{}
	conn.sendKeyUpdateUpdateRequested = false // must not be necessary
	// now when we received ack for KeyUpdate, we must update our keys
	conn.Keys.Send.ComputeNextApplicationTrafficSecret(conn.RoleServer) // next application traffic secret is calculated from the previous one
	conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
	conn.Keys.Send.Symmetric.Epoch++
	conn.Keys.SendNextSegmentSequence = 0
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
		if !conn.Keys.ExpectReceiveEpochUpdate || !hdr.MatchesEpoch(receiver.Symmetric.Epoch+1) {
			return // simply ignore, probably garbage or keys from previous epoch
		}
		// We check here that receiver.Epoch+1 does not overflow, because we increment it below
		if receiver.Symmetric.Epoch == math.MaxUint16 {
			err = dtlserrors.ErrUpdatingKeysWouldOverflowEpoch
			return
		}
		// We should not believe new epoch bits before we decrypt record successfully,
		// so we have to calculate new keys here. But if we fail decryption, then we
		// either should store new keys, or recompute them on each (attacker's) packet.
		// So, we decided we better store new keys
		if !conn.Keys.NewReceiveKeysSet {
			conn.Keys.NewReceiveKeysSet = true
			conn.Keys.NewReceiveKeys.Epoch = receiver.Symmetric.Epoch + 1
			conn.Keys.NewReceiveKeys.ComputeKeys(receiver.ApplicationTrafficSecret[:])
			conn.Keys.FailedDeprotectionCounterNewReceiveKeys = 0
			receiver.ComputeNextApplicationTrafficSecret(!conn.RoleServer) // next application traffic secret is calculated from the previous one
		}
		decrypted, seq, contentType, err = conn.Keys.NewReceiveKeys.Deprotect(hdr, !conn.Keys.DoNotEncryptSequenceNumbers, 0,
			seqNumData, header, body)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			conn.Keys.FailedDeprotectionCounterNewReceiveKeys++
			return
		}
		conn.Keys.ExpectReceiveEpochUpdate = false
		receiver.Symmetric = conn.Keys.NewReceiveKeys // epoch is also copied
		conn.Keys.ReceiveNextSegmentSequence.Reset()
		_ = conn.Keys.ReceiveNextSegmentSequence.SetReceivedIsUnique(seq + 1) // always unique
		conn.Keys.FailedDeprotectionCounter = conn.Keys.FailedDeprotectionCounterNewReceiveKeys
		conn.Keys.NewReceiveKeys = keys.SymmetricKeys{} // remove alias
		conn.Keys.NewReceiveKeysSet = false
		conn.Keys.FailedDeprotectionCounterNewReceiveKeys = 0
		conn.Keys.RequestedReceiveEpochUpdate = false
	}
	rn = format.RecordNumberWith(receiver.Symmetric.Epoch, seq)
	return
}

// update receiving keys does not always work with wolf
// TODO - investigate, seems one of us has incorrect state machine
func (conn *ConnectionImpl) checkReceiveLimits() error {
	receiveLimit := conn.Keys.SequenceNumberLimit()
	if conn.Keys.FailedDeprotectionCounterNewReceiveKeys >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflowNextEpoch
	}
	// we cannot request update of NewReceiveKeys, but if peer rotates them before
	// error above, we will request update.
	receivedCurrentEpoch := conn.Keys.FailedDeprotectionCounter + conn.Keys.ReceiveNextSegmentSequence.GetNextReceivedSeq()
	if receivedCurrentEpoch >= receiveLimit {
		return dtlserrors.ErrReceiveRecordSeqOverflow
	}
	if conn.Keys.Receive.Symmetric.Epoch < 3 || receivedCurrentEpoch < receiveLimit*3/4 { // simple heuristics
		return nil
	}
	if conn.Keys.RequestedReceiveEpochUpdate {
		return nil
	}
	conn.Keys.RequestedReceiveEpochUpdate = true
	return conn.startKeyUpdate(true)
}

func (conn *ConnectionImpl) ProcessCiphertextRecord(opts *options.TransportOptions, hdr format.CiphertextRecordHeader, cid []byte, seqNumData []byte, header []byte, body []byte) error {
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
	// [rfc9147:4.1], but it seems acks must always be encrypted in DTLS1.3, so we do not classify them as valid here
	switch contentType {
	case format.PlaintextContentTypeAlert:
		return conn.ProcessAlert(true, opts, decrypted)
	case format.PlaintextContentTypeAck:
		return conn.ProcessEncryptedAck(opts, decrypted)
	case format.PlaintextContentTypeApplicationData:
		return conn.ProcessApplicationData(opts, decrypted)
	case format.PlaintextContentTypeHandshake:
		return conn.ProcessEncryptedHandshake(opts, decrypted, rn)
	}
	return dtlserrors.ErrUnknownInnerPlaintextRecordType
}

func (conn *ConnectionImpl) ProcessAlert(encrypted bool, opts *options.TransportOptions, messageData []byte) error {
	// TODO - beware of unencrypted alert!
	log.Printf("dtls: got alert record (encrypted=%v) %d bytes from %v, message(hex): %x", encrypted, len(messageData), conn.Addr, messageData)
	// messageData must be 2 bytes, TODO - parse and process alert
	// record with an Alert type MUST contain exactly one message. [rfc8446:5.1]
	return nil
}

func (conn *ConnectionImpl) ProcessEncryptedAck(opts *options.TransportOptions, messageData []byte) error {
	insideBody, err := format.ParseMessageAcks(messageData)
	if err != nil {
		return dtlserrors.ErrEncryptedAckMessageHeaderParsing
	}
	log.Printf("dtls: got ack record (encrypted) %d bytes from %v, message(hex): %x", len(messageData), conn.Addr, messageData)
	conn.ReceiveAcks(opts, insideBody)
	// if all messages from epoch 2 acked, then switch sending epoch
	if conn.Handshake != nil && conn.Handshake.SendQueue.Len() == 0 && conn.Keys.Send.Symmetric.Epoch == 2 {
		conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
		conn.Keys.Send.Symmetric.Epoch = 3
		conn.Keys.SendNextSegmentSequence = 0
		conn.Handshake = nil // TODO - reuse into pool
		conn.Handler = &exampleHandler{toSend: "Hello from client\n"}
		conn.HandlerHasMoreData = true
	}
	return nil // ack occupies full record
}

func (conn *ConnectionImpl) ProcessApplicationData(opts *options.TransportOptions, messageData []byte) error {
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

func (conn *ConnectionImpl) ProcessEncryptedHandshake(opts *options.TransportOptions, recordData []byte, rn format.RecordNumber) error {
	log.Printf("dtls: got handshake record (encrypted) %d bytes from %v, message(hex): %x", len(recordData), conn.Addr, recordData)
	if len(recordData) == 0 {
		// [rfc8446:5.1] Implementations MUST NOT send zero-length fragments of Handshake types, even if those fragments contain padding
		return dtlserrors.ErrHandshakeReecordEmpty
	}
	messageOffset := 0 // there are two acceptable ways to pack two DTLS handshake messages into the same datagram: in the same record or in separate records [rfc9147:5.5]
	for messageOffset < len(recordData) {
		var handshakeHdr format.MessageHandshakeHeader
		n, messageBody, err := handshakeHdr.ParseWithBody(recordData[messageOffset:])
		if err != nil {
			opts.Stats.BadMessageHeader("handshake(encrypted)", messageOffset, len(recordData), conn.Addr, err)
			return dtlserrors.ErrEncryptedHandshakeMessageHeaderParsing
		}
		messageOffset += n
		if conn.Handshake != nil {
			flight := HandshakeTypeToFlight(handshakeHdr.HandshakeType, conn.RoleServer) // zero if unknown
			conn.Handshake.ReceivedFlight(conn, flight)
			// receiving any chunk from the next flight will remove all acks for previous flights
			// before this and subsequent chunks are added to hctx.acks
		}
		switch handshakeHdr.HandshakeType {
		case format.HandshakeTypeClientHello:
			opts.Stats.MustNotBeEncrypted("handshake(encrypted)", format.HandshakeTypeToName(handshakeHdr.HandshakeType), conn.Addr, handshakeHdr)
			return dtlserrors.ErrClientHelloMustNotBeEncrypted
		case format.HandshakeTypeServerHello:
			opts.Stats.MustNotBeEncrypted("handshake(encrypted)", format.HandshakeTypeToName(handshakeHdr.HandshakeType), conn.Addr, handshakeHdr)
			return dtlserrors.ErrServerHelloMustNotBeEncrypted
		case format.HandshakeTypeNewSessionTicket:
			if err := conn.receivedNewSessionTicket(opts, handshakeHdr, messageBody, rn); err != nil {
				return err
			}
		case format.HandshakeTypeKeyUpdate:
			if err := conn.receivedKeyUpdate(opts, handshakeHdr, messageBody, rn); err != nil {
				return err
			}
		default:
			if err := conn.Handshake.ReceivedMessage(conn, handshakeHdr, messageBody, rn); err != nil {
				return err
			}
		}
	}
	return nil
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
