// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package statemachine

import (
	"slices"
	"testing"

	"github.com/hrissan/dtls/circular"
	"github.com/hrissan/dtls/handshake"
	"github.com/hrissan/dtls/record"
)

// linear search is faster for small arrays

// so we keep sentRecords not sorted (they are mixed with epoch 0)

//cpu: 13th Gen Intel(R) Core(TM) i7-1360P
//BenchmarkSendQueue_AckLinear16-16     	149360463	         7.960 ns/op
//BenchmarkSendQueue_AckLog16-16        	73486818	        16.32 ns/op
//BenchmarkSendQueue_AckLinear64-16     	35143996	        31.50 ns/op
//BenchmarkSendQueue_AckLog64-16        	49088563	        23.87 ns/op
//BenchmarkSendQueue_AckLinear256-16    	 9869287	       122.5 ns/op
//BenchmarkSendQueue_AckLog256-16       	38059436	        31.12 ns/op

func findSentRecordIndexExt2(elements []record2Fragment, sentRecords *circular.BufferExt[record2Fragment], rn record.Number) *handshake.FragmentInfo {
	s1, s2 := sentRecords.Slices(elements)

	if ind, ok := slices.BinarySearchFunc(s1, rn, relationPred); ok {
		return &s1[ind].fragment
	}
	if ind, ok := slices.BinarySearchFunc(s2, rn, relationPred); ok {
		return &s2[ind].fragment
	}
	return nil
}

func prepareBufferExtForTests(elements []record2Fragment) *circular.BufferExt[record2Fragment] {
	size := len(elements)
	sentRecords := &circular.BufferExt[record2Fragment]{}
	for i := 0; i < size*3/4; i++ {
		sentRecords.PushBack(elements, record2Fragment{})
	}
	for i := 0; i < size*3/4; i++ {
		sentRecords.PopFront(elements)
	}
	for i := 0; i < size; i++ {
		rn := record.NumberWith(1, uint64(i)) // widening
		if i%2 == 0 {
			sentRecords.PushBack(elements, record2Fragment{rn: rn})
		}
	}
	return sentRecords
}

func TestSendQueue_AckExt(t *testing.T) {
	var elements [32]record2Fragment
	sentRecords := prepareBufferExtForTests(elements[:])
	for i := 0; i < 30; i++ {
		rn := record.NumberWith(1, uint64(i)) // widening
		fragmentPtr1 := findSentRecordIndexExt(elements[:], sentRecords, rn)
		fragmentPtr2 := findSentRecordIndexExt2(elements[:], sentRecords, rn)
		if fragmentPtr1 != fragmentPtr2 {
			t.Fatalf("findSentRecordIndexExt and findSentRecordIndex2 differ")
		}
		if i%2 == 0 && fragmentPtr1 == nil {
			t.Fatalf("must find")
		}
		if i%2 != 0 && fragmentPtr1 != nil {
			t.Fatalf("must not find")
		}
	}
}

func BenchmarkSendQueue_AckExtLinear16(b *testing.B) {
	var elements [16]record2Fragment
	sentRecords := prepareBufferExtForTests(elements[:])
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndexExt(elements[:], sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckExtLog16(b *testing.B) {
	var elements [16]record2Fragment
	sentRecords := prepareBufferExtForTests(elements[:])
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndexExt2(elements[:], sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckExtLinear64(b *testing.B) {
	var elements [64]record2Fragment
	sentRecords := prepareBufferExtForTests(elements[:])
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndexExt(elements[:], sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckExtLog64(b *testing.B) {
	var elements [64]record2Fragment
	sentRecords := prepareBufferExtForTests(elements[:])
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndexExt2(elements[:], sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckExtLinear256(b *testing.B) {
	var elements [256]record2Fragment
	sentRecords := prepareBufferExtForTests(elements[:])
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndexExt(elements[:], sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckExtLog256(b *testing.B) {
	var elements [256]record2Fragment
	sentRecords := prepareBufferExtForTests(elements[:])
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndexExt2(elements[:], sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}
