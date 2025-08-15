package receiver

import (
	"log"
	"math"
	"net/netip"

	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
)

func (rc *Receiver) deprotectCiphertextRecord(hdr format.CiphertextRecordHeader, cid []byte, seqNumData []byte, header []byte, body []byte, addr netip.AddrPort) {
	log.Printf("dtls: got ciphertext %v cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, body)
	rc.handMu.Lock()
	defer rc.handMu.Unlock()
	hctx := rc.handshakes[addr]
	if hctx == nil {
		// TODO - send alert here
		return
	}
	receiver := &hctx.Keys.Receive
	var decrypted []byte
	var seq uint64
	var contentType byte
	var err error
	if hdr.MatchesEpoch(receiver.Epoch) {
		decrypted, seq, contentType, err = receiver.Symmetric.Deprotect(hdr, !hctx.Keys.DoNotEncryptSequenceNumbers, hctx.Keys.Receive.NextSegmentSequence,
			seqNumData, header, body)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			hctx.Keys.FailedDeprotectionCounter++
			return
		}
		hctx.Keys.Receive.NextSegmentSequence = seq + 1 // TODO - update replay window
	} else {
		// We should check here that receiver.Epoch+1 does not overflow, because we increment it below
		if !hctx.Keys.ExpectEpochUpdate || receiver.Epoch == math.MaxUint16 || !hdr.MatchesEpoch(receiver.Epoch+1) {
			return // TODO - alert, either garbage, attack or epoch wrapping
		}
		// We should not believe new epoch bits before we decrypt record successfully,
		// so we have to calculate new keys here. But if we fail decryption, then we
		// either should store new keys, or recompute them on each (attacker's) packet.
		// So, we decided we better store new keys
		if !hctx.Keys.NewReceiveKeysSet {
			hctx.Keys.NewReceiveKeysSet = true
			hctx.Keys.NewReceiveKeys.ComputeKeys(receiver.ApplicationTrafficSecret[:])
			hctx.Keys.NewReceiveKeysFailedDeprotectionCounter = 0
		}
		decrypted, seq, contentType, err = hctx.Keys.NewReceiveKeys.Deprotect(hdr, !hctx.Keys.DoNotEncryptSequenceNumbers, 0,
			seqNumData, header, body)
		if err != nil {
			// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
			hctx.Keys.NewReceiveKeysFailedDeprotectionCounter++
			return
		}
		hctx.Keys.Receive.Symmetric = hctx.Keys.NewReceiveKeys
		hctx.Keys.FailedDeprotectionCounter = hctx.Keys.NewReceiveKeysFailedDeprotectionCounter
		hctx.Keys.NewReceiveKeys = keys.SymmetricKeys{} // remove alias
		hctx.Keys.NewReceiveKeysSet = false
		hctx.Keys.NewReceiveKeysFailedDeprotectionCounter = 0
		hctx.Keys.Receive.NextSegmentSequence = 1 // TODO - update replay window
		hctx.Keys.Receive.Epoch++
	}
	log.Printf("dtls: ciphertext %d deprotected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
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
				rc.opts.Stats.BadMessageHeader("handshake(encrypted)", messageOffset, len(decrypted), addr, err)
				// TODO: alert here, and we cannot continue to the next record.
				return
			}
			messageData = messageData[:n]
			messageOffset += n
			if handshakeHdr.HandshakeType == format.HandshakeTypeClientHello || handshakeHdr.HandshakeType == format.HandshakeTypeServerHello {
				rc.opts.Stats.MustNotBeEncrypted("handshake(encrypted)", format.HandshakeTypeToName(handshakeHdr.HandshakeType), addr, handshakeHdr)
				// TODO: alert here, and we do not want to continue to the next record.
				return
			}
			registerInSender := hctx.ReceivedMessage(handshakeHdr, body)
			if registerInSender {
				rc.snd.RegisterConnectionForSend(hctx) // TODO - postpone all responses until full datagram processed
			}
		case format.PlaintextContentTypeAck:
			log.Printf("dtls: got ack(encrypted) %v from %v, message(hex): %x", hdr, addr, messageData)
			// TODO - if all messages from epoch 2 acked, then switch sending epoch
			if hctx.Keys.Send.Epoch == 2 {
				hctx.Keys.Send.Symmetric.ComputeKeys(hctx.Keys.Send.ApplicationTrafficSecret[:])
				hctx.Keys.Send.Epoch++
				hctx.Keys.Send.NextSegmentSequence = 0
			}
			return // TODO - more checks
		case format.PlaintextContentTypeApplicationData:
			log.Printf("dtls: got application_data(encrypted) %v from %v, message(hex): %x", hdr, addr, messageData)
			return // TODO - more checks
		default: // never, because checked in format.IsPlaintextRecord()
			panic("unknown content type")
		}
	}
}
