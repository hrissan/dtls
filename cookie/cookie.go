// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package cookie

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/hkdf"
)

const cookieHashLength = sha256.Size
const saltLength = 16 // arguably, this is enough

type CookieState struct {
	cookieSecret [32]byte      // [rfc9147:5.1]
	rnd          dtlsrand.Rand // for salt
}

const MaxCookieSize = 256

type Cookie struct {
	data [MaxCookieSize]byte // maximum supported size
	size int
}

type Params struct {
	// those values are signed, so server can trust them after validation
	TranscriptHash    [constants.MaxHashLength]byte
	TimestampUnixNano int64
	KeyShareSet       bool
}

func (p *Params) IsValidTimestamp(now time.Time, cookieValidDuration time.Duration) (time.Duration, bool) {
	unixNanoNow := now.UnixNano()
	if p.TimestampUnixNano > unixNanoNow { // cookie from the future
		return 0, false
	}
	age := time.Duration(unixNanoNow - p.TimestampUnixNano)
	return age, age <= cookieValidDuration

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
	rnd.ReadMust(c.cookieSecret[:])
}

func (c *CookieState) CreateCookie(params Params, addr netip.AddrPort) Cookie {
	var cookie Cookie
	{
		var salt [saltLength]byte
		c.rnd.ReadMust(salt[:])
		cookie.AppendMust(salt[:])
	}
	{
		var unixNanoBytes [8]byte
		binary.BigEndian.PutUint64(unixNanoBytes[:], uint64(params.TimestampUnixNano))
		cookie.AppendMust(unixNanoBytes[:])
	}
	if params.KeyShareSet { // to reconstruct stateless HRR, we must remember if we asked for alternative key_share
		cookie.AppendByteMust(1)
	} else {
		cookie.AppendByteMust(0)
	}
	cookie.AppendMust(params.TranscriptHash[:])

	hash := c.getScratchHash(cookie.GetValue(), addr)
	cookie.AppendMust(hash[:])

	return cookie
}

func (c *CookieState) IsCookieValid(addr netip.AddrPort, cookie Cookie) (_ Params, ok bool) {
	var params Params
	data := cookie.GetValue()
	if len(data) != saltLength+8+1+constants.MaxHashLength+cookieHashLength {
		return
	}
	params.TimestampUnixNano = int64(binary.BigEndian.Uint64(data[saltLength:]))
	params.KeyShareSet = data[saltLength+8] != 0
	copy(params.TranscriptHash[:], data[saltLength+8+1:])

	var mustBeHash [cookieHashLength]byte
	copy(mustBeHash[:], data[saltLength+8+1+constants.MaxHashLength:])

	hash := c.getScratchHash(data[:saltLength+8+1+constants.MaxHashLength], addr)
	if hash != mustBeHash {
		return Params{}, false
	}
	return params, true
}

func (c *CookieState) getScratchHash(cookieHashedBytes []byte, addr netip.AddrPort) [cookieHashLength]byte {
	scratch := make([]byte, 0, MaxCookieSize+cookieHashLength) // allocate on stack
	scratch = append(scratch, cookieHashedBytes...)
	b := addr.Addr().As16()
	scratch = append(scratch, b[:]...)
	scratch = binary.BigEndian.AppendUint16(scratch, addr.Port())
	if len(scratch) > MaxCookieSize+cookieHashLength {
		panic("please increase maxScratchSize")
	}
	hmac := hkdf.HMAC(c.cookieSecret[:], scratch, sha256.New())
	if len(hmac) != cookieHashLength {
		panic("bad hmac")
	}
	var result [cookieHashLength]byte
	copy(result[:], hmac)
	return result
}
