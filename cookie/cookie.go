package cookie

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"time"
)

const scratchSize = 32 + 32 + 16 + 2 + 8

type CookieState struct {
	cookieSecret [32]byte // [rfc9147:5.1]
}

type Cookie [40]byte

func (c *CookieState) SetRandomSecret() {
	if _, err := rand.Read(c.cookieSecret[:]); err != nil {
		panic("failed to read cookie secret crypto rand: " + err.Error())
	}
}

func (c *CookieState) CreateCookie(clientRandom [32]byte, addr netip.AddrPort, now time.Time) Cookie {
	scratch := make([]byte, 0, scratchSize)
	scratch = c.appendScratch(scratch, clientRandom, addr, uint64(now.UnixNano()))
	hash := sha256.Sum256(scratch)

	var result Cookie
	copy(result[:], scratch[len(scratch)-8:])
	copy(result[8:], hash[:])
	return result
}

func (c *CookieState) IsCookieValidBytes(clientRandom [32]byte, addr netip.AddrPort, cookieBytes []byte) bool {
	var cookie Cookie
	if copy(cookie[:], cookieBytes[:]) != len(cookie) {
		return false
	}
	return c.IsCookieValid(clientRandom, addr, cookie)
}

func (c *CookieState) IsCookieValid(clientRandom [32]byte, addr netip.AddrPort, cookie Cookie) bool {
	unixNano := binary.BigEndian.Uint64(cookie[:])
	var mustBeHash [32]byte
	copy(mustBeHash[:], cookie[8:])

	scratch := make([]byte, 0, scratchSize)
	scratch = c.appendScratch(scratch, clientRandom, addr, unixNano)
	hash := sha256.Sum256(scratch)
	return hash == mustBeHash
}

func (c *CookieState) appendScratch(scratch []byte, clientRandom [32]byte, addr netip.AddrPort, unixNano uint64) []byte {
	scratch = append(scratch, clientRandom[:]...)
	scratch = append(scratch, c.cookieSecret[:]...)
	b := addr.Addr().As16()
	scratch = append(scratch, b[:]...)
	scratch = binary.BigEndian.AppendUint16(scratch, addr.Port())

	scratch = binary.BigEndian.AppendUint64(scratch, unixNano)
	return scratch
}
