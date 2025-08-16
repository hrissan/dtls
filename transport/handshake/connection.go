package handshake

import (
	"errors"
	"log"
	"math"
	"net/netip"
	"sync"

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
	InSenderQueue bool // intrusive, must not be changed except by sender, protected by sender mutex

	// variables below mu are protected by mu
	mu         sync.Mutex     // TODO - check that mutex is alwasy taken
	Addr       netip.AddrPort // changes very rarely
	RoleServer bool           // changes very rarely
	Keys       keys.Keys
	// ConnectionImpl is owned by Receiver, Calculator and User.
	// Reused once refCount reached 0
	// ConnectionImpl pointer can still stay in Sender and Clock, but
	// closed bool // if true, every owner releases connection
	// refCount byte - TODO
	// inCalculator bool - TODO
	Handshake *HandshakeConnection // content is also protected by mutex above
	Handler   ConnectionHandler
}

func (conn *ConnectionImpl) ConstructDatagram(datagram []byte) (datagramSize int, addToSendQueue bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.Handshake != nil {
		datagramSize, addToSendQueue = conn.Handshake.ConstructDatagram(conn, datagram)
		if datagramSize > 0 {
			return // do not mix - TODO - mix
		}
	}
	// TODO - application data
	// if conn.handler != nil {
	//	recordSize, send, add := conn.handler.OnWriteApplicationRecord(datagram)
	// }
	return
}

var ErrUpdatingKeysWouldOverflowEpoch = errors.New("updating keys would overflow epoch")

func (conn *ConnectionImpl) receivedNewSessionTicket(handshakeHdr format.MessageHandshakeHeader, body []byte) (registerInSender bool) {
	if handshakeHdr.IsFragmented() {
		// alert - we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		return
	}
	if conn.Handshake != nil {
		return // alert - post-handshake message prohibited during handshake
	}
	if handshakeHdr.MessageSeq != conn.Keys.NextMessageSeqReceive {
		return // totally ok to ignore
	}
	conn.Keys.NextMessageSeqReceive++
	log.Printf("received and ignored NewSessionTicket") // TODO
	return
}

func (conn *ConnectionImpl) receivedKeyUpdate(handshakeHdr format.MessageHandshakeHeader, body []byte) (registerInSender bool) {
	if handshakeHdr.IsFragmented() {
		// alert - we do not support fragmented post handshake messages, because we do not want to allocate storage for them.
		// They are short though, so we do not ack them, there is chance peer will resend them in full
		return
	}
	if conn.Handshake != nil {
		return // alert - post-handshake message prohibited during handshake
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
	if hdr.MatchesEpoch(receiver.Epoch) {
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
		if !conn.Keys.ExpectEpochUpdate || receiver.Epoch == math.MaxUint16 || !hdr.MatchesEpoch(receiver.Epoch+1) {
			err = ErrUpdatingKeysWouldOverflowEpoch
			return
		}
		// We should not believe new epoch bits before we decrypt record successfully,
		// so we have to calculate new keys here. But if we fail decryption, then we
		// either should store new keys, or recompute them on each (attacker's) packet.
		// So, we decided we better store new keys
		if !conn.Keys.NewReceiveKeysSet {
			conn.Keys.NewReceiveKeysSet = true
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
		receiver.Symmetric = conn.Keys.NewReceiveKeys
		receiver.NextSegmentSequence = 1 // TODO - update replay window
		receiver.Epoch++
		conn.Keys.FailedDeprotectionCounter = conn.Keys.NewReceiveKeysFailedDeprotectionCounter
		conn.Keys.NewReceiveKeys = keys.SymmetricKeys{} // remove alias
		conn.Keys.NewReceiveKeysSet = false
		conn.Keys.NewReceiveKeysFailedDeprotectionCounter = 0
	}
	rn = format.RecordNumberWith(receiver.Epoch, seq)
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
				registerInSender = conn.receivedNewSessionTicket(handshakeHdr, body)
				continue
			case format.HandshakeTypeKeyUpdate:
				registerInSender = conn.receivedKeyUpdate(handshakeHdr, body)
				continue
			}
			if conn.Handshake != nil {
				registerInSender = conn.Handshake.ReceivedMessage(conn, handshakeHdr, body, rn) || registerInSender
			}
		case format.PlaintextContentTypeAck:
			log.Printf("dtls: got ack(encrypted) %v from %v, message(hex): %x", hdr, addr, messageData)
			// TODO - if all messages from epoch 2 acked, then switch sending epoch
			if conn.Keys.Send.Epoch == 2 {
				conn.Keys.Send.Symmetric.ComputeKeys(conn.Keys.Send.ApplicationTrafficSecret[:])
				conn.Keys.Send.Epoch++
				conn.Keys.Send.NextSegmentSequence = 0
			}
			return // TODO - more checks
		case format.PlaintextContentTypeApplicationData:
			log.Printf("dtls: got application_data(encrypted) %v from %v, message(hex): %x", hdr, addr, messageData)
			return // TODO - more checks
		default: // never, because checked in format.IsPlaintextRecord()
			panic("unknown content type")
		}
	}
	return
}
