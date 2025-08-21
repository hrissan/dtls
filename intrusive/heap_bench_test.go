package intrusive_test

import (
	"math/rand/v2"
	"testing"

	"github.com/hrissan/dtls/intrusive"
)

// comparison with btree
//BenchmarkInsertAsc-16            	106345168	        10.59 ns/op	       0 B/op	       0 allocs/op
//BenchmarkInsertDesc-16           	18676468	        70.08 ns/op	       0 B/op	       0 allocs/op
//BenchmarkInsertRandom-16         	56231749	        20.99 ns/op	       0 B/op	       0 allocs/op
//BenchmarkEraseAsc-16             	 8029796	       192.9 ns/op	       0 B/op	       0 allocs/op
//BenchmarkEraseDesc-16            	301588987	         3.715 ns/op	       0 B/op	       0 allocs/op
//BenchmarkInsertAscBTree-16       	 7096374	       177.1 ns/op	      36 B/op	       0 allocs/op
//BenchmarkInsertDescBTree-16      	 8275224	       158.1 ns/op	      16 B/op	       0 allocs/op
//BenchmarkInsertRandomBTree-16    	 2082777	       775.8 ns/op	      23 B/op	       0 allocs/op
//BenchmarkEraseAscBTree-16        	 9647838	       141.6 ns/op	       0 B/op	       0 allocs/op
//BenchmarkEraseDescBTree-16       	 8180128	       164.3 ns/op	      19 B/op	       0 allocs/op

func prepareHeap(size int) ([]testObject, *intrusive.IntrusiveHeap[testObject]) {
	objects := make([]testObject, size)
	for i := 0; i < size; i++ {
		objects[i].Value = i
	}
	heap := intrusive.NewIntrusiveHeap[testObject](func(i *testObject, i2 *testObject) bool {
		return i.Value < i2.Value
	}, size)
	return objects, heap
}

func BenchmarkInsertAsc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkInsertDesc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkInsertRandom(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	rand.Shuffle(len(objects), func(i, j int) { objects[i], objects[j] = objects[j], objects[i] })
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkEraseAsc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		heap.Erase(&objects[n], &objects[n].HeapIndex)
	}
}

func BenchmarkEraseDesc(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		heap.Erase(&objects[n], &objects[n].HeapIndex)
	}
}

/*
func BenchmarkEraseRandom(b *testing.B) {
	b.ReportAllocs()
	objects, heap := prepareHeap(b.N)
	for n := 0; n < b.N; n++ {
		heap.Insert(&objects[n], &objects[n].HeapIndex)
	}
	rand.Shuffle(len(objects), func(i, j int) { objects[i], objects[j] = objects[j], objects[i] })
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		heap.Erase(&objects[n], &objects[n].HeapIndex)
	}
}
*/

/*
func prepareBTree(size int) *btree.BTreeG[*testObject] {
	b := btree.NewG[*testObject](10, func(a, b *testObject) bool {
		return a.Value < b.Value
	})
	return b
}

func BenchmarkInsertAscBTree(b *testing.B) {
	b.ReportAllocs()
	objects, _ := prepareHeap(b.N)
	tree := prepareBTree(b.N)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		tree.ReplaceOrInsert(&objects[n])
	}
}

func BenchmarkInsertDescBTree(b *testing.B) {
	b.ReportAllocs()
	objects, _ := prepareHeap(b.N)
	tree := prepareBTree(b.N)
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		tree.ReplaceOrInsert(&objects[n])
	}
}

func BenchmarkInsertRandomBTree(b *testing.B) {
	b.ReportAllocs()
	objects, _ := prepareHeap(b.N)
	rand.Shuffle(len(objects), func(i, j int) { objects[i], objects[j] = objects[j], objects[i] })
	tree := prepareBTree(b.N)
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		tree.ReplaceOrInsert(&objects[n])
	}
}

func BenchmarkEraseAscBTree(b *testing.B) {
	b.ReportAllocs()
	objects, _ := prepareHeap(b.N)
	tree := prepareBTree(b.N)
	for n := 0; n < b.N; n++ {
		tree.ReplaceOrInsert(&objects[n])
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		tree.Delete(&objects[n])
	}
}

func BenchmarkEraseDescBTree(b *testing.B) {
	b.ReportAllocs()
	objects, _ := prepareHeap(b.N)
	tree := prepareBTree(b.N)
	for n := b.N - 1; n >= 0; n-- {
		tree.ReplaceOrInsert(&objects[n])
	}
	b.ResetTimer()
	for n := b.N - 1; n >= 0; n-- {
		tree.Delete(&objects[n])
	}
}
*/
