package cookie

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"time"

	"github.com/hrissan/tinydtls/dtlsrand"
)

const MaxTranscriptHashLength = 64 // TODO - replace with constants.MaxHashLength
const cookieHashLength = sha256.Size
const saltLength = 24

type CookieState struct {
	cookieSecret [32]byte // [rfc9147:5.1]
	rnd          dtlsrand.Rand
}

const MaxCookieSize = 256

type Cookie struct {
	data [MaxCookieSize]byte // maximum supported size
	size int
}

var ErrCookieDataTooLong = errors.New("cookie data is too long")

func (c *Cookie) GetValue() []byte {
	return c.data[0:c.size]
}

func (c *Cookie) SetValue(data []byte) error {
	if len(data) > MaxCookieSize {
		return ErrCookieDataTooLong
	}
	c.size = len(data)
	copy(c.data[:], data)
	return nil
}

func (c *Cookie) AppendMust(data []byte) {
	if c.size+len(data) > MaxCookieSize {
		panic(ErrCookieDataTooLong)
	}
	copy(c.data[c.size:], data)
	c.size += len(data)
}

func (c *Cookie) AppendByteMust(data byte) {
	if c.size+1 > MaxCookieSize {
		panic(ErrCookieDataTooLong)
	}
	c.data[c.size] = data
	c.size += 1
}

func (c *CookieState) SetRand(rnd dtlsrand.Rand) {
	c.rnd = rnd
	rnd.Read(c.cookieSecret[:])
}

func (c *CookieState) CreateCookie(transcriptHash [MaxTranscriptHashLength]byte, keyShareSet bool, addr netip.AddrPort, now time.Time) Cookie {
	var cookie Cookie
	{
		var salt [saltLength]byte
		c.rnd.Read(salt[:])
		cookie.AppendMust(salt[:])
	}
	{
		var unixNanoBytes [8]byte
		unixNano := uint64(now.UnixNano())
		binary.BigEndian.PutUint64(unixNanoBytes[:], unixNano)
		cookie.AppendMust(unixNanoBytes[:])
	}
	if keyShareSet { // to reconstruct stateless HRR, we must remember if we asked for alternative key_share
		cookie.AppendByteMust(1)
	} else {
		cookie.AppendByteMust(0)
	}
	cookie.AppendMust(transcriptHash[:])

	hash := c.getScratchHash(cookie.GetValue(), addr)
	cookie.AppendMust(hash[:])

	return cookie
}

func (c *CookieState) IsCookieValid(addr netip.AddrPort, cookie Cookie, now time.Time) (ok bool, age time.Duration, transcriptHash [MaxTranscriptHashLength]byte, keyShareSet bool) {
	data := cookie.GetValue()
	if len(data) != saltLength+8+1+MaxTranscriptHashLength+cookieHashLength {
		return
	}
	unixNanoNow := uint64(now.UnixNano())
	unixNano := binary.BigEndian.Uint64(data[saltLength:])
	if unixNano > unixNanoNow { // cookie from the future
		return
	}
	if unixNanoNow-unixNano > math.MaxInt64 { // time.Duration overflow
		return
	}
	age = time.Duration(unixNanoNow - unixNano)
	keyShareSet = data[saltLength+8] != 0
	copy(transcriptHash[:], data[saltLength+8+1:])

	var mustBeHash [cookieHashLength]byte
	copy(mustBeHash[:], data[saltLength+8+1+MaxTranscriptHashLength:])

	hash := c.getScratchHash(data[:saltLength+8+1+MaxTranscriptHashLength], addr)
	ok = hash == mustBeHash
	return
}

func (c *CookieState) getScratchHash(cookieHashedBytes []byte, addr netip.AddrPort) [cookieHashLength]byte {
	scratch := make([]byte, 0, MaxCookieSize+cookieHashLength) // allocate on stack
	scratch = append(scratch, cookieHashedBytes...)
	scratch = append(scratch, c.cookieSecret[:]...) // secret in the middle. IDK if this important, but feels better.
	b := addr.Addr().As16()
	scratch = append(scratch, b[:]...)
	scratch = binary.BigEndian.AppendUint16(scratch, addr.Port())
	if len(scratch) > MaxCookieSize+cookieHashLength {
		panic("please increase maxScratchSize")
	}
	return sha256.Sum256(scratch)
}
