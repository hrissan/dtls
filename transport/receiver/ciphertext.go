package receiver

import (
	"encoding/binary"
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/format"
)

func (rc *Receiver) processCiphertextRecord(hdr format.CiphertextRecordHeader, cid []byte, seqNumData []byte, header []byte, body []byte, addr netip.AddrPort) {
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
	if err := hctx.Keys.EncryptSequenceNumbers(seqNumData, body, rc.opts.RoleServer); err != nil {
		return // TODO - send alert here
	}
	gcm := hctx.Keys.ServerWrite
	iv := hctx.Keys.ServerWriteIV
	if rc.opts.RoleServer {
		gcm = hctx.Keys.ClientWrite
		iv = hctx.Keys.ClientWriteIV
	}
	var sniv [12]byte
	seq := hdr.ClosestSequenceNumber(seqNumData, hctx.Keys.NextSegmentSequenceReceive)
	binary.BigEndian.PutUint64(sniv[4:], seq)
	for i, b := range iv {
		sniv[i] ^= b
	}
	decrypted, err := gcm.Open(body[:0], sniv[:], body, header)
	if err != nil {
		// failed deprotection, alas
		return
	}
	log.Printf("dtls: ciphertext %d deprotected cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, decrypted)
}
