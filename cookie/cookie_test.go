// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package cookie_test

import (
	"crypto/sha256"
	"net/netip"
	"testing"
	"time"

	"github.com/hrissan/dtls/cookie"
	"github.com/hrissan/dtls/dtlsrand"
)

func TestRoundTrip(t *testing.T) {
	var state cookie.CookieState
	state.SetRand(dtlsrand.CryptoRand())
	addr, err := netip.ParseAddrPort("1.2.3.4:5")
	now := time.Now()
	if err != nil {
		t.FailNow()
	}
	params := cookie.Params{
		TranscriptHash:    sha256.Sum256([]byte("test")),
		TimestampUnixNano: now.UnixNano(),
		KeyShareSet:       true,
		Age:               time.Second,
	}
	ck := state.CreateCookie(params, addr)

	params2, err := state.IsCookieValid(addr, ck, now.Add(time.Second), time.Minute)
	if err != nil {
		t.FailNow()
	}
	if params != params2 {
		t.FailNow()
	}
}
