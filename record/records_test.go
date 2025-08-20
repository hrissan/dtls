// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package record

import (
	"math"
	"testing"
)

func TestClosestSeq(t *testing.T) {
	for expectedSN := uint64(3969); expectedSN < 0x1000; expectedSN++ {
		for seq := uint64(0); seq < 256; seq++ {
			closest := closestSequenceNumber(uint16(seq), expectedSN, 0x100)
			minDistance := 1e6
			var bestCandidate uint64
			for highPart := uint64(0); highPart <= 0x1000; highPart += 0x100 {
				candidate := highPart + seq
				distance := math.Abs(float64(candidate) - float64(expectedSN))
				if distance == minDistance && candidate < bestCandidate {
					t.FailNow() // of 2 equal solutions, we want the smaller one
				}
				if distance < minDistance {
					minDistance = distance
					bestCandidate = candidate
				}
			}
			if bestCandidate != closest {
				t.FailNow()
			}
		}
	}
}
