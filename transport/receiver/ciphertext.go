package receiver

import (
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/format"
	"github.com/hrissan/tinydtls/keys"
)

// TODO - optimize
// contentType is the first non-zero byte from the end
func findPaddingOffsetContentType(data []byte) (paddingOffset int, contentType byte) {
	for i := len(data) - 1; i >= 0; i-- {
		b := data[i]
		if b != 0 {
			return i, b
		}
	}
	return -1, 0
}

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
	if byte(receiver.Epoch&0b00000011) != hdr.Epoch() {
		if !hctx.Keys.ExpectEpochUpdate {
			return // TODO - alert, either garbage or attack
		}
		// We should not believe new epoch bits before we decrypt record successfully,
		// so we have to calculate new keys here. But if we fail decryption, then we
		// either should store new keys, or recompute them on each (attacker's) packet.
		// So, we decided we have to store new keys
		// var NewKeys keys.SymmetricKeys
		return // TODO - switch epoch after key update only
	}
	if !hctx.Keys.DoNotEncryptSequenceNumbers {
		if err := receiver.Symmetric.EncryptSequenceNumbers(seqNumData, body); err != nil {
			return // TODO - send alert here
		}
	}
	gcm := receiver.Symmetric.Write
	iv := receiver.Symmetric.WriteIV // copy, otherwise disaster
	decryptedSeq, seq := hdr.ClosestSequenceNumber(seqNumData, hctx.Keys.Receive.NextSegmentSequence)
	log.Printf("decrypted SN: %d, closest: %d", decryptedSeq, seq)

	keys.FillIVSequence(iv[:], seq)
	decrypted, err := gcm.Open(body[:0], iv[:], body, header)
	if err != nil {
		// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
		hctx.Keys.FailedDeprotectionCounter++
		return
	}
	hctx.Keys.Receive.NextSegmentSequence = seq + 1 // TODO - update replay window
	log.Printf("dtls: ciphertext %d deprotected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
	paddingOffset, contentType := findPaddingOffsetContentType(decrypted) // [rfc8446:5.4]
	if paddingOffset < 0 || !format.IsInnerPlaintextRecord(contentType) {
		// TODO - send alert
		return
	}
	decrypted = decrypted[:paddingOffset]
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
			return // TODO - more checks
		case format.PlaintextContentTypeApplicationData:
			log.Printf("dtls: got application_data(encrypted) %v from %v, message(hex): %x", hdr, addr, messageData)
			return // TODO - more checks
		default: // never, because checked in format.IsPlaintextRecord()
			panic("unknown content type")
		}
	}
}
