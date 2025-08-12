package receiver

import (
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/format"
)

func (rc *Receiver) processCiphertextRecord(hdr format.CiphertextRecordHeader, cid []byte, body []byte, addr netip.AddrPort) {
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
	if err := hctx.Keys.EncryptSequenceNumbers(&hdr, body, rc.opts.RoleServer); err != nil {
		return // TODO - send alert here
	}
}
