// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"net/netip"
	"sync"
	"time"

	"github.com/hrissan/dtls/ciphersuite"
	"github.com/hrissan/dtls/dtlserrors"
	"github.com/hrissan/dtls/dtlsrand"
	"github.com/hrissan/dtls/format"
	"github.com/hrissan/dtls/safecast"
)

const cookieHashLength = sha256.Size
const saltLength = 16 // arguably, this is enough

type CookieState struct {
	// [rfc9147:5.1]
	mu         sync.Mutex // we want to reuse hasher below
	hmacHasher hash.Hash
	rnd        dtlsrand.Rand // for salt
}

const MaxCookieSize = 256

type Cookie struct {
	data [MaxCookieSize]byte // maximum supported size
	size int
}

type Params struct {
	// those values are signed, so server can trust them after validation
	TranscriptHash    ciphersuite.Hash
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
	if len(data) > len(c.data) {
		return ErrCookieDataTooLong
	}
	*c = Cookie{size: len(data)} // clear data, so objects are equal by built-int operator
	copy(c.data[:], data)
	return nil
}

func (c *Cookie) AppendMust(data []byte) {
	if c.size+len(data) > len(c.data) {
		panic(ErrCookieDataTooLong)
	}
	copy(c.data[c.size:], data)
	c.size += len(data)
}

func (c *Cookie) AppendByteMust(data byte) {
	if c.size+1 > len(c.data) {
		panic(ErrCookieDataTooLong)
	}
	c.data[c.size] = data
	c.size += 1
}

func (c *CookieState) SetRand(rnd dtlsrand.Rand) {
	c.rnd = rnd

	var cookieSecret [32]byte
	rnd.ReadMust(cookieSecret[:])

	c.mu.Lock()
	defer c.mu.Unlock()
	c.hmacHasher = hmac.New(sha256.New, cookieSecret[:])
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
	cookie.AppendByteMust(safecast.Cast[byte](params.TranscriptHash.Len()))
	cookie.AppendMust(params.TranscriptHash.GetValue()[:])

	actualHash := c.getScratchHash(cookie.GetValue(), addr)
	cookie.AppendMust(actualHash[:])

	return cookie
}

func (c *CookieState) IsCookieValid(addr netip.AddrPort, cookie Cookie, now time.Time, cookieValidDuration time.Duration) (_ Params, err error) {
	// Important to return empty params below in case of error,
	// so we accidentally do not use them if forgot to check ok.
	var params Params
	data := cookie.GetValue()
	offset := 0
	var salt [saltLength]byte // value ignored
	if offset, err = format.ParserReadFixedBytes(data, offset, salt[:]); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	var timestampUnixNano uint64
	if offset, timestampUnixNano, err = format.ParserReadUint64(data, offset); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	params.TimestampUnixNano = int64(timestampUnixNano)
	var keyShareSet byte
	if offset, keyShareSet, err = format.ParserReadByte(data, offset); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	params.KeyShareSet = keyShareSet != 0
	var cipherSuite uint16
	if offset, cipherSuite, err = format.ParserReadUint16(data, offset); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	params.CipherSuite = ciphersuite.ID(cipherSuite)
	var transcriptHashLen byte
	if offset, transcriptHashLen, err = format.ParserReadByte(data, offset); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	if int(transcriptHashLen) > params.TranscriptHash.Cap() {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	params.TranscriptHash.SetZero(int(transcriptHashLen))
	if offset, err = format.ParserReadFixedBytes(data, offset, params.TranscriptHash.GetValue()); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}

	actualHash := c.getScratchHash(data[:offset], addr)

	var mustBeHash [cookieHashLength]byte
	if offset, err = format.ParserReadFixedBytes(data, offset, mustBeHash[:]); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	if offset != len(data) {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}

	unixNanoNow := now.UnixNano()
	if params.TimestampUnixNano > unixNanoNow { // cookie from the future
		return Params{}, dtlserrors.ErrClientHelloCookieAge
	}
	params.Age = time.Duration(unixNanoNow - params.TimestampUnixNano)
	if params.Age >= cookieValidDuration {
		return Params{}, dtlserrors.ErrClientHelloCookieAge
	}
	if actualHash != mustBeHash {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	return params, nil
}

func (c *CookieState) getScratchHash(cookieHashedBytes []byte, addr netip.AddrPort) [cookieHashLength]byte {
	scratch := make([]byte, 0, 2*MaxCookieSize) // allocate on stack
	scratch = append(scratch, cookieHashedBytes...)
	// Treating as equal actual ipv4 address and one mapped to ipv6 seems to be good enough for us here
	b := addr.Addr().As16()
	scratch = append(scratch, b[:]...)
	scratch = binary.BigEndian.AppendUint16(scratch, addr.Port())
	if len(scratch) > 2*MaxCookieSize {
		panic("please increase maxScratchSize")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.hmacHasher.Reset()
	c.hmacHasher.Write(scratch)

	var result [cookieHashLength]byte
	_ = c.hmacHasher.Sum(result[:0])
	return result
}
