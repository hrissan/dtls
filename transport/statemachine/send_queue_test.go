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

var benchmarkSideEffect = 0

func relationPred(relation record2Fragment, rn record.Number) int {
	return record.RecordNumberCmp(relation.rn, rn)
}

func findSentRecordIndex2(sentRecords *circular.Buffer[record2Fragment], rn record.Number) *handshake.FragmentInfo {
	s1, s2 := sentRecords.Slices()

	if ind, ok := slices.BinarySearchFunc(s1, rn, relationPred); ok {
		return &s1[ind].fragment
	}
	if ind, ok := slices.BinarySearchFunc(s2, rn, relationPred); ok {
		return &s2[ind].fragment
	}
	return nil
}

func prepareBufferForTests(elements int) *circular.Buffer[record2Fragment] {
	sentRecords := &circular.Buffer[record2Fragment]{}
	sentRecords.Reserve(elements)
	for i := 0; i < elements*3/4; i++ {
		sentRecords.PushBack(record2Fragment{})
	}
	for i := 0; i < elements*3/4; i++ {
		sentRecords.PopFront()
	}
	for i := 0; i < elements; i++ {
		rn := record.NumberWith(1, uint64(i))
		if i%2 == 0 {
			sentRecords.PushBack(record2Fragment{rn: rn})
		}
	}
	return sentRecords
}

func TestSendQueue_Ack(t *testing.T) {
	sentRecords := prepareBufferForTests(32)
	for i := 0; i < 30; i++ {
		rn := record.NumberWith(1, uint64(i))
		fragmentPtr1 := findSentRecordIndex(sentRecords, rn)
		fragmentPtr2 := findSentRecordIndex2(sentRecords, rn)
		if fragmentPtr1 != fragmentPtr2 {
			t.Fatalf("findSentRecordIndex and findSentRecordIndex2 differ")
		}
		if i%2 == 0 && fragmentPtr1 == nil {
			t.Fatalf("must find")
		}
		if i%2 != 0 && fragmentPtr1 != nil {
			t.Fatalf("must not find")
		}
	}
}

func BenchmarkSendQueue_AckLinear16(b *testing.B) {
	sentRecords := prepareBufferForTests(16)
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndex(sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckLog16(b *testing.B) {
	sentRecords := prepareBufferForTests(16)
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndex2(sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckLinear64(b *testing.B) {
	sentRecords := prepareBufferForTests(64)
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndex(sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckLog64(b *testing.B) {
	sentRecords := prepareBufferForTests(64)
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndex2(sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckLinear256(b *testing.B) {
	sentRecords := prepareBufferForTests(256)
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndex(sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}

func BenchmarkSendQueue_AckLog256(b *testing.B) {
	sentRecords := prepareBufferForTests(256)
	for n := 0; n < b.N; n++ {
		fragmentPtr := findSentRecordIndex2(sentRecords, record.NumberWith(1, uint64(n)))
		if fragmentPtr != nil {
			benchmarkSideEffect++ // side effect
		}
	}
}
