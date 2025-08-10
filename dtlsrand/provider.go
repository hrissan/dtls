package dtlsrand

import "crypto/rand"

// We need to fix randoms for tests, hence abstraction

type Rand interface {
	Read(data []byte)
}

type cryptoRand struct {
}

func (c *cryptoRand) Read(data []byte) {
	if _, err := rand.Read(data); err != nil {
		panic("failed to read cookie secret crypto rand: " + err.Error())
	}
}

type fixedRand struct {
}

func (c *fixedRand) Read(data []byte) {
	for i := range data {
		data[i] = byte(i)
	}
}

func CryptoRand() Rand {
	return &cryptoRand{}
}

func FixedRand() Rand {
	return &fixedRand{}
}
