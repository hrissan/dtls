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
	transcriptHash := sha256.Sum256([]byte("test"))
	addr, err := netip.ParseAddrPort("1.2.3.4:5")
	now := time.Now()
	if err != nil {
		t.FailNow()
	}
	ck := state.CreateCookie(transcriptHash, true, addr, now)

	ok, age, transcriptHash2, keyShareSet := state.IsCookieValid(addr, ck, now.Add(time.Second))
	if !ok {
		t.FailNow()
	}
	if transcriptHash != transcriptHash2 {
		t.FailNow()
	}
	if !keyShareSet {
		t.FailNow()
	}
	if age != time.Second {
		t.FailNow()
	}
}
