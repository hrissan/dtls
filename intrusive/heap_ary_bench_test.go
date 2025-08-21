package intrusive_test

import (
	"math/rand/v2"
	"testing"

	"github.com/hrissan/dtls/intrusive"
)

// comparison with btree
//BenchmarkAryInsertAsc-16            	106345168	        10.59 ns/op	       0 B/op	       0 allocs/op
//BenchmarkAryInsertDesc-16           	18676468	        70.08 ns/op	       0 B/op	       0 allocs/op
//BenchmarkAryInsertRandom-16         	56231749	        20.99 ns/op	       0 B/op	       0 allocs/op
//BenchmarkAryEraseAsc-16             	 8029796	       192.9 ns/op	       0 B/op	       0 allocs/op
//BenchmarkAryEraseDesc-16            	301588987	         3.715 ns/op	       0 B/op	       0 allocs/op
//BenchmarkAryInsertAscBTree-16       	 7096374	       177.1 ns/op	      36 B/op	       0 allocs/op
//BenchmarkAryInsertDescBTree-16      	 8275224	       158.1 ns/op	      16 B/op	       0 allocs/op
//BenchmarkAryInsertRandomBTree-16    	 2082777	       775.8 ns/op	      23 B/op	       0 allocs/op
//BenchmarkAryEraseAscBTree-16        	 9647838	       141.6 ns/op	       0 B/op	       0 allocs/op
//BenchmarkAryEraseDescBTree-16       	 8180128	       164.3 ns/op	      19 B/op	       0 allocs/op

func prepareHeapAry(size int) ([]testObject, *intrusive.IntrusiveHeapAry[testObject]) {
	objects := make([]testObject, size)
	for i := 0; i < size; i++ {
		objects[i].Value = i
	}
	heap := intrusive.NewIntrusiveHeapAry[testObject](func(i *testObject, i2 *testObject) bool {
		return i.Value < i2.Value
	}, size)
	return objects, heap
}

func BenchmarkAryInsertAsc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeapAry(b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkAryInsertDesc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeapAry(b.N)
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkAryInsertRandom(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeapAry(b.N)
	rand.Shuffle(len(objects), func(i, j int) { objects[i], objects[j] = objects[j], objects[i] })
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkAryEraseAsc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeapAry(b.N)
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		heap.PopFront()
		//heap.Erase(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkAryEraseDesc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeapAry(b.N)
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		heap.PopFront()
		//heap.Erase(&objects[n], &objects[n].HeapIndex)
	}
}
