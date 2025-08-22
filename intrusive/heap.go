// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package intrusive

// Intrusive heap has O(ln2(N)) complexity of pop_front, insert, delete
// and coefficient is small
// for critical latency apps reserve() must be called to avoid reallocation

// Intrusive heap stores index in stored object field
// index == 0 is special value and means "not in a heap"
// Unlike intrusive list, it does not allow unlinking object without reference to heap

// This is min heap, so if less is used, front will be the smallest element

// due to Go limitations, we actually store 2 separate pointer,
// one to heap element, another to intrusive index.
// distance between them unsafe.Pointer(a) - unsafe.Pointer(b) is always the same for given type.
// but we do not want to use unsafe here.
// BTW: storing interface values would take the same 2 pointers, plus be slower due to interface calls.

const healthChecks = false

type pair[T any] struct {
	ptr        *T
	heap_index *int
}

type IntrusiveHeap[T any] struct {
	storage []pair[T] // element 0 is reserved, so heap_index 0 means "not in heap"
	pred    func(*T, *T) bool
}

// pred is heap predicate (Less)
func NewIntrusiveHeap[T any](pred func(*T, *T) bool, size int) *IntrusiveHeap[T] {
	return &IntrusiveHeap[T]{
		pred:    pred,
		storage: make([]pair[T], 0, size),
	}
}

func (h *IntrusiveHeap[T]) Reserve(size int) {
	if cap(h.storage) >= size {
		return
	}
	storage := h.storage
	h.storage = make([]pair[T], len(storage), size)
	copy(h.storage, storage)
}

func (h *IntrusiveHeap[T]) Len() int {
	return len(h.storage)
}

func (h *IntrusiveHeap[T]) Front() *T {
	if healthChecks && *h.storage[0].heap_index != 1 {
		panic("heap invariant violated")
	}
	return h.storage[0].ptr
}

func (h *IntrusiveHeap[T]) Insert(node *T, heap_index *int) bool {
	if *heap_index != 0 {
		return false
	}
	h.storage = append(h.storage, pair[T]{node, heap_index})
	h.moveUp(len(h.storage) - 1)
	h.checkHeap()
	return true
}

func (h *IntrusiveHeap[T]) Erase(node *T, heap_index *int) bool {
	if *heap_index == 0 {
		return false
	}
	ind := *heap_index - 1
	if h.storage[ind] != (pair[T]{node, heap_index}) {
		// this is user's invariant, we want to keep it to debug business logic
		panic("heap invariant violated")
	}
	*heap_index = 0
	h.popBackToIndex(ind)
	if ind < len(h.storage) {
		h.adjust(ind)
	}
	h.checkHeap()
	return true
}

func (h *IntrusiveHeap[T]) PopFront() {
	ind := *h.storage[0].heap_index
	if healthChecks && ind != 1 {
		panic("heap invariant violated")
	}
	*h.storage[0].heap_index = 0
	h.popBackToIndex(0)
	if len(h.storage) > 0 {
		h.moveDown(0)
	}
	h.checkHeap()
}

func (h *IntrusiveHeap[T]) popBackToIndex(ind int) {
	h.storage[ind] = h.storage[len(h.storage)-1]
	h.storage[len(h.storage)-1] = pair[T]{nil, nil} // do not leave aliases
	h.storage = h.storage[:len(h.storage)-1]
}

func (h *IntrusiveHeap[T]) checkHeap() {
	if !healthChecks {
		return
	}
	for i := 0; i < len(h.storage); i++ {
		if *h.storage[i].heap_index != i+1 {
			panic("heap invariant violated")
		}
	}
	if h.isHeapUntil(h.storage) != len(h.storage) {
		panic("heap invariant violated")
	}
}

func (h *IntrusiveHeap[T]) isHeapUntil(storage []pair[T]) int {
	p := 0
	for c := 1; c < len(storage); c++ {
		if !h.pred(storage[p].ptr, storage[c].ptr) {
			return c
		}
		if (c & 1) == 0 {
			p++
		}
	}
	return len(storage)
}

func (h *IntrusiveHeap[T]) adjust(ind int) {
	if ind > 0 && h.pred(h.storage[ind].ptr, h.storage[(ind-1)/2].ptr) {
		h.moveUp(ind)
	} else {
		h.moveDown(ind)
	}
}

func (h *IntrusiveHeap[T]) moveDown(ind int) {
	size := len(h.storage)
	data := h.storage[ind]

	for {
		lc := ind*2 + 1
		if lc >= size {
			break
		}

		if lc+1 < size && !h.pred(h.storage[lc].ptr, h.storage[lc+1].ptr) {
			lc++
		}

		if !h.pred(h.storage[lc].ptr, data.ptr) {
			break
		}
		h.storage[ind] = h.storage[lc]
		*h.storage[ind].heap_index = ind + 1

		ind = lc
	}
	h.storage[ind] = data
	*h.storage[ind].heap_index = ind + 1
}

func (h *IntrusiveHeap[T]) moveUp(ind int) {
	data := h.storage[ind]

	for ind > 0 {
		p := (ind - 1) / 2

		if !h.pred(data.ptr, h.storage[p].ptr) {
			break
		}
		h.storage[ind] = h.storage[p]
		*h.storage[ind].heap_index = ind + 1
		ind = p
	}
	h.storage[ind] = data
	*h.storage[ind].heap_index = ind + 1
}
