package receiver

import (
	"log"
	"net/netip"

	"github.com/hrissan/tinydtls/format"
)

func (rc *Receiver) processCiphertextRecord(hdr format.CiphertextRecordHeader, cid []byte, body []byte, addr netip.AddrPort) {
	log.Printf("dtls: got ciphertext %v cid(hex): %x from %v, body(hex): %x", hdr, cid, addr, body)
}
