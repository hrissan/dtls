// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package dtlsrand

import (
	"crypto/rand"
	"io"
)

// We need to fix randoms for tests, plus do not want to check error every time

type Rand interface {
	io.Reader
	ReadMust(data []byte)
}

type cryptoRand struct {
}

func (c *cryptoRand) Read(data []byte) (n int, err error) {
	return rand.Read(data)
}

func (c *cryptoRand) ReadMust(data []byte) {
	if _, err := c.Read(data); err != nil {
		panic("failed to read cookie secret crypto rand: " + err.Error())
	}
}

type fixedRand struct {
	offset int
}

func (c *fixedRand) ReadMust(data []byte) {
	for i := range data {
		data[i] = byte(c.offset) // truncate
		c.offset++
	}
}

func (c *fixedRand) Read(data []byte) (n int, err error) {
	c.ReadMust(data)
	return len(data), nil
}

func CryptoRand() Rand {
	return &cryptoRand{}
}

func FixedRand() Rand {
	return &fixedRand{}
}
