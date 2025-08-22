package intrusive

const mult = 4

type IntrusiveHeapAry[T any] struct {
	storage []pair[T]
	pred    func(*T, *T) bool
}

// pred is heap predicate (Less)
func NewIntrusiveHeapAry[T any](pred func(*T, *T) bool, size int) *IntrusiveHeapAry[T] {
	return &IntrusiveHeapAry[T]{
		pred:    pred,
		storage: make([]pair[T], 0, size),
	}
}

func (h *IntrusiveHeapAry[T]) Reserve(size int) {
	if cap(h.storage) >= size {
		return
	}
	storage := h.storage
	h.storage = make([]pair[T], len(storage), size)
	copy(h.storage, storage)
}

func (h *IntrusiveHeapAry[T]) Len() int {
	return len(h.storage)
}

func (h *IntrusiveHeapAry[T]) Front() *T {
	if healthChecks && *h.storage[0].heap_index != 1 {
		panic("heap invariant violated")
	}
	return h.storage[0].ptr
}

func (h *IntrusiveHeapAry[T]) moveIn(index uint, value pair[T]) {
	if healthChecks && *value.heap_index != 0 {
		panic("heap invariant violated")
	}
	if healthChecks && h.storage[index] != (pair[T]{}) {
		panic("heap invariant violated")
	}
	*value.heap_index = int(index + 1)
	h.storage[index] = value
}

func (h *IntrusiveHeapAry[T]) moveOut(index uint) pair[T] {
	heapIndex := uint(*h.storage[index].heap_index)
	if healthChecks && heapIndex != index+1 {
		panic("heap invariant violated")
	}
	value := h.storage[index]
	if healthChecks {
		*h.storage[index].heap_index = 0
		h.storage[index] = pair[T]{nil, nil}
	}
	return value
}

func (h *IntrusiveHeapAry[T]) Insert(node *T, heap_index *int) bool {
	if *heap_index != 0 {
		return false
	}
	h.storage = append(h.storage, pair[T]{})
	index := uint(len(h.storage) - 1)
	value := pair[T]{node, heap_index}
	h.moveUp(index, value)
	return true
}

func (h *IntrusiveHeapAry[T]) moveUp(index uint, value pair[T]) {
	for index > 0 {
		parent := parentIndex(index)
		if h.pred(h.storage[parent].ptr, value.ptr) {
			break
		}
		tmp := h.moveOut(parent)
		h.moveIn(index, tmp)
		index = parent
	}
	h.moveIn(index, value)
	h.checkHeap()
}

func (h *IntrusiveHeapAry[T]) Erase(node *T, heap_index *int) bool {
	if *heap_index == 0 {
		return false
	}
	h.checkHeap()
	index := uint(*heap_index) - 1
	erased := h.moveOut(index)
	if index == uint(len(h.storage))-1 {
		h.storage = h.storage[:index]
		h.checkHeap()
		return true
	}
	length := uint(len(h.storage) - 1)
	value := h.moveOut(length)
	h.storage = h.storage[:length]
	if h.pred(erased.ptr, value.ptr) {
		h.moveDown(index, length, value)
	} else {
		h.moveUp(index, value)
	}
	h.checkHeap()
	return true
}

func (h *IntrusiveHeapAry[T]) PopFront() {
	_ = h.moveOut(0)
	if len(h.storage) == 1 {
		h.storage = h.storage[:0]
		h.checkHeap()
		return
	}

	length := uint(len(h.storage) - 1)
	value := h.moveOut(length)
	h.storage = h.storage[:length]
	h.moveDown(0, length, value)
}

func (h *IntrusiveHeapAry[T]) moveDown(index uint, length uint, value pair[T]) {
	for {
		lastChild := lastChildIndex(index)
		firstChild := lastChild - mult + 1
		if lastChild < length {
			largestChild := h.largestChildFullRec(mult, firstChild)
			if h.pred(value.ptr, h.storage[largestChild].ptr) {
				break
			}
			tmp := h.moveOut(largestChild)
			h.moveIn(index, tmp)
			index = largestChild
		} else if firstChild < length {
			largestChild := h.largestChildPartialRec(mult, firstChild, length-firstChild)
			if !h.pred(value.ptr, h.storage[largestChild].ptr) {
				tmp := h.moveOut(largestChild)
				h.moveIn(index, tmp)
				index = largestChild
			}
			break
		} else {
			break
		}
	}
	h.moveIn(index, value)
	h.checkHeap()
}

func (h *IntrusiveHeapAry[T]) popBackToIndex(ind int) {
	h.storage[ind] = h.storage[len(h.storage)-1]
	h.storage[len(h.storage)-1] = pair[T]{nil, nil} // do not leave aliases
	h.storage = h.storage[:len(h.storage)-1]
}

func (h *IntrusiveHeapAry[T]) checkHeap() {
	if !healthChecks {
		return
	}
	for i := 0; i < len(h.storage); i++ {
		if *h.storage[i].heap_index != i+1 {
			panic("heap invariant violated")
		}
	}
	if !h.isHeap() {
		panic("heap invariant violated")
	}
}

func (h *IntrusiveHeapAry[T]) isHeap() bool {
	length := uint(len(h.storage))
	for i := uint(1); i < length; i++ {
		parent := parentIndex(i)
		if !h.pred(h.storage[parent].ptr, h.storage[i].ptr) {
			return false
		}
	}
	return true
}

func firstChildIndex(index uint) uint {
	return index*mult + 1
}

func lastChildIndex(index uint) uint {
	return index*mult + mult
}

func parentIndex(index uint) uint {
	return (index - 1) / mult
}

func bool2uint(a bool) uint {
	if a {
		return 1
	}
	return 0
}

func (h *IntrusiveHeapAry[T]) largestChildFullRec(multArg uint, firstChild uint) uint {
	switch multArg {
	case 1:
		return firstChild
	case 2:
		return firstChild + bool2uint(!h.pred(h.storage[firstChild].ptr, h.storage[firstChild+1].ptr))
	default:
		firstHalfLargest := h.largestChildFullRec(multArg/2, firstChild)
		secondHalfLargest := h.largestChildFullRec(multArg-multArg/2, firstChild+multArg/2)
		if !h.pred(h.storage[firstHalfLargest].ptr, h.storage[secondHalfLargest].ptr) {
			return secondHalfLargest
		}
		return firstHalfLargest
	}
}

func (h *IntrusiveHeapAry[T]) largestChildPartialRec(multArg uint, firstChild uint, numChildren uint) uint {
	switch multArg {
	case 1, 2: // 1 - never
		return firstChild
	case 3:
		if numChildren == 1 {
			return firstChild
		}
		return firstChild + bool2uint(!h.pred(h.storage[firstChild].ptr, h.storage[firstChild+1].ptr))
	case 4:
		switch numChildren {
		case 1:
			return firstChild
		case 2:
			return firstChild + bool2uint(!h.pred(h.storage[firstChild].ptr, h.storage[firstChild+1].ptr))
		}
		largest := firstChild + bool2uint(!h.pred(h.storage[firstChild].ptr, h.storage[firstChild+1].ptr))
		if !h.pred(h.storage[largest].ptr, h.storage[firstChild+2].ptr) {
			return firstChild + 2
		}
		return largest
	default:
		panic("later")
	}
}
