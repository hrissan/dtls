// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package cookie

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/constants"
	"github.com/hrissan/dtls/dtlserrors"
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
	KeyShareSet       bool           // we must remember to generate exactly same HRR for transcript
	CipherSuite       ciphersuite.ID // we must remember to generate exactly same HRR for transcript
	Age               time.Duration  // set during validation
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
		binary.BigEndian.PutUint64(unixNanoBytes[:], uint64(params.TimestampUnixNano)) // type conversion
		cookie.AppendMust(unixNanoBytes[:])
	}
	if params.KeyShareSet { // to reconstruct stateless HRR, we must remember if we asked for alternative key_share
		cookie.AppendByteMust(1)
	} else {
		cookie.AppendByteMust(0)
	}
	{
		var suiteBytes [2]byte
		binary.BigEndian.PutUint16(suiteBytes[:], uint16(params.CipherSuite))
		cookie.AppendMust(suiteBytes[:])
	}
	cookie.AppendMust(params.TranscriptHash[:])

	hash := c.getScratchHash(cookie.GetValue(), addr)
	cookie.AppendMust(hash[:])

	return cookie
}

func (c *CookieState) IsCookieValid(addr netip.AddrPort, cookie Cookie, now time.Time, cookieValidDuration time.Duration) (_ Params, err error) {
	var params Params
	data := cookie.GetValue()
	if len(data) != saltLength+8+1+2+constants.MaxHashLength+cookieHashLength {
		return
	}
	params.TimestampUnixNano = int64(binary.BigEndian.Uint64(data[saltLength:]))
	params.KeyShareSet = data[saltLength+8] != 0
	params.CipherSuite = ciphersuite.ID(binary.BigEndian.Uint16(data[saltLength+8+1:]))
	copy(params.TranscriptHash[:], data[saltLength+8+3:])

	unixNanoNow := now.UnixNano()
	if params.TimestampUnixNano > unixNanoNow { // cookie from the future
		return Params{}, dtlserrors.ErrClientHelloCookieAge
	}
	params.Age = time.Duration(unixNanoNow - params.TimestampUnixNano)
	if params.Age >= cookieValidDuration {
		return Params{}, dtlserrors.ErrClientHelloCookieAge
	}

	var mustBeHash [cookieHashLength]byte
	copy(mustBeHash[:], data[saltLength+8+3+constants.MaxHashLength:])

	hash := c.getScratchHash(data[:saltLength+8+3+constants.MaxHashLength], addr)
	if hash != mustBeHash {
		// important to return empty params, so we accidentally do not use them if forgot to check ok
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	return params, nil
}

func (c *CookieState) getScratchHash(cookieHashedBytes []byte, addr netip.AddrPort) [cookieHashLength]byte {
	scratch := make([]byte, 0, MaxCookieSize+cookieHashLength) // allocate on stack
	scratch = append(scratch, cookieHashedBytes...)
	b := addr.Addr().As16() // TODO - remember exact IP address type
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
