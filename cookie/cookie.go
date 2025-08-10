package cookie

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"net/netip"
	"time"
)

const MaxTranscriptHashLength = 64
const cookieHashLength = sha256.Size
const saltLength = 24

type CookieState struct {
	cookieSecret [32]byte // [rfc9147:5.1]
}

type Cookie [saltLength + 8 + MaxTranscriptHashLength + cookieHashLength]byte // salt | unixNano | ...

func (c *CookieState) SetRandomSecret() {
	if _, err := rand.Read(c.cookieSecret[:]); err != nil {
		panic("failed to read cookie secret crypto rand: " + err.Error())
	}
}

func (c *CookieState) CreateCookie(transcriptHash [MaxTranscriptHashLength]byte, addr netip.AddrPort, now time.Time) Cookie {
	var cookie Cookie
	if _, err := rand.Read(cookie[:saltLength]); err != nil {
		panic("failed to read random salt: " + err.Error())
	}
	unixNano := uint64(now.UnixNano())
	binary.BigEndian.PutUint64(cookie[saltLength:], unixNano)
	copy(cookie[saltLength+8:], transcriptHash[:])

	hash := c.getScratchHash(cookie[:saltLength+8+MaxTranscriptHashLength], addr)
	copy(cookie[saltLength+8+MaxTranscriptHashLength:], hash[:])

	return cookie
}

func (c *CookieState) IsCookieValid(addr netip.AddrPort, cookie Cookie, now time.Time) (ok bool, age time.Duration, transcriptHash [MaxTranscriptHashLength]byte) {
	unixNanoNow := uint64(now.UnixNano())
	unixNano := binary.BigEndian.Uint64(cookie[saltLength:])
	if unixNano > unixNanoNow { // cookie from the future
		return
	}
	if unixNanoNow-unixNano > math.MaxInt64 { // time.Duration overflow
		return
	}
	age = time.Duration(unixNanoNow - unixNano)
	copy(transcriptHash[:], cookie[saltLength+8:])

	var mustBeHash [cookieHashLength]byte
	copy(mustBeHash[:], cookie[saltLength+8+MaxTranscriptHashLength:])

	hash := c.getScratchHash(cookie[:saltLength+8+MaxTranscriptHashLength], addr)
	ok = hash == mustBeHash
	return
}

func (c *CookieState) getScratchHash(cookieHashedBytes []byte, addr netip.AddrPort) [cookieHashLength]byte {
	const maxScratchSize = saltLength + 8 + MaxTranscriptHashLength + 16 + 2 + cookieHashLength
	scratch := make([]byte, 0, maxScratchSize) // allocate on stack
	scratch = append(scratch, cookieHashedBytes...)
	scratch = append(scratch, c.cookieSecret[:]...) // secret in the middle. IDK if this important, but feels better.
	b := addr.Addr().As16()
	scratch = append(scratch, b[:]...)
	scratch = binary.BigEndian.AppendUint16(scratch, addr.Port())
	return sha256.Sum256(scratch)
}
