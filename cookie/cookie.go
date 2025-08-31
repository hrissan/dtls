// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package cookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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

const CookieStorageSize = 256

type Params struct {
	// those values are signed, so server can trust them after validation
	TranscriptHash    ciphersuite.Hash
	TimestampUnixNano int64
	KeyShareSet       bool           // we must remember to generate exactly same HRR for transcript
	CipherSuite       ciphersuite.ID // we must remember to generate exactly same HRR for transcript
	Age               time.Duration  // set during validation
}

func (c *CookieState) SetRand(rnd dtlsrand.Rand) {
	c.rnd = rnd

	var cookieSecret [32]byte
	rnd.ReadMust(cookieSecret[:])

	c.mu.Lock()
	defer c.mu.Unlock()
	c.hmacHasher = hmac.New(sha256.New, cookieSecret[:])
}

func (c *CookieState) AppendCookie(cookie []byte, params Params, addr netip.AddrPort) []byte {
	{
		var salt [saltLength]byte
		c.rnd.ReadMust(salt[:])
		cookie = append(cookie, salt[:]...)
	}
	cookie = binary.BigEndian.AppendUint64(cookie, uint64(params.TimestampUnixNano)) // type conversion
	if params.KeyShareSet {                                                          // to reconstruct stateless HRR, we must remember if we asked for alternative key_share
		cookie = append(cookie, 1)
	} else {
		cookie = append(cookie, 0)
	}
	cookie = binary.BigEndian.AppendUint16(cookie, uint16(params.CipherSuite))
	cookie = append(cookie, safecast.Cast[byte](params.TranscriptHash.Len()))
	cookie = append(cookie, params.TranscriptHash.GetValue()...)

	actualHash := c.getScratchHash(cookie, addr)
	cookie = append(cookie, actualHash[:]...)

	return cookie
}

func (c *CookieState) IsCookieValid(addr netip.AddrPort, cookie []byte, now time.Time, cookieValidDuration time.Duration) (_ Params, err error) {
	// Important to return empty params below in case of error,
	// so we accidentally do not use them if forgot to check ok.
	var params Params
	offset := 0
	var salt [saltLength]byte // value ignored
	if offset, err = format.ParserReadFixedBytes(cookie, offset, salt[:]); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	var timestampUnixNano uint64
	if offset, timestampUnixNano, err = format.ParserReadUint64(cookie, offset); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	params.TimestampUnixNano = int64(timestampUnixNano)
	var keyShareSet byte
	if offset, keyShareSet, err = format.ParserReadByte(cookie, offset); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	params.KeyShareSet = keyShareSet != 0
	var cipherSuite uint16
	if offset, cipherSuite, err = format.ParserReadUint16(cookie, offset); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	params.CipherSuite = ciphersuite.ID(cipherSuite)
	var transcriptHashLen byte
	if offset, transcriptHashLen, err = format.ParserReadByte(cookie, offset); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	if int(transcriptHashLen) > params.TranscriptHash.Cap() {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	params.TranscriptHash.SetZero(int(transcriptHashLen))
	if offset, err = format.ParserReadFixedBytes(cookie, offset, params.TranscriptHash.GetValue()); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}

	actualHash := c.getScratchHash(cookie[:offset], addr)

	var mustBeHash [cookieHashLength]byte
	if offset, err = format.ParserReadFixedBytes(cookie, offset, mustBeHash[:]); err != nil {
		return Params{}, dtlserrors.ErrClientHelloCookieInvalid
	}
	if offset != len(cookie) {
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
	scratch := make([]byte, 0, 2*CookieStorageSize) // allocate on stack

	scratch = append(scratch, cookieHashedBytes...)
	// Treating as equal actual ipv4 address and one mapped to ipv6 seems to be good enough for us here
	b := addr.Addr().As16()
	scratch = append(scratch, b[:]...)
	scratch = binary.BigEndian.AppendUint16(scratch, addr.Port())
	if len(scratch) > 2*CookieStorageSize {
		panic("please increase scratch size")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.hmacHasher.Reset()
	c.hmacHasher.Write(scratch)

	var result [cookieHashLength]byte
	_ = c.hmacHasher.Sum(result[:0])
	return result
}
