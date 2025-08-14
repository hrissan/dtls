package receiver

import (
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/format"
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
	if byte(hctx.Keys.Epoch&0b00000011) != hdr.Epoch() {
		return // TODO - switch epoch after key update only
	}
	if err := hctx.Keys.DecryptSequenceNumbers(seqNumData, body, rc.opts.RoleServer); err != nil {
		return // TODO - send alert here
	}
	gcm := hctx.Keys.ServerWrite
	iv := hctx.Keys.ServerWriteIV // copy, otherwise disaster
	if rc.opts.RoleServer {
		gcm = hctx.Keys.ClientWrite
		iv = hctx.Keys.ClientWriteIV // copy, otherwise disaster
	}
	decryptedSeq, seq := hdr.ClosestSequenceNumber(seqNumData, hctx.Keys.NextSegmentSequenceReceive)
	log.Printf("decrypted SN: %d, closest: %d", decryptedSeq, seq)

	hctx.Keys.FillIVSequence(iv[:], seq)
	decrypted, err := gcm.Open(body[:0], iv[:], body, header)
	if err != nil {
		// [rfc9147:4.5.3] TODO - check against AEAD limit, initiate key update well before reaching limit, and close connection if limit reached
		hctx.Keys.FailDeprotection++
		return
	}
	hctx.Keys.NextSegmentSequenceReceive++
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
			hctx.ReceivedMessage(handshakeHdr, body)
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
