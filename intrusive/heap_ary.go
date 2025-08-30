// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

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

func moveIn[T any](storage []pair[T], index uint, value pair[T]) {
	if healthChecks && *value.heap_index != 0 {
		panic("heap invariant violated")
	}
	if healthChecks && storage[index] != (pair[T]{}) {
		panic("heap invariant violated")
	}
	*value.heap_index = int(index + 1)
	storage[index] = value
}

func moveOut[T any](storage []pair[T], index uint) pair[T] {
	heapIndex := uint(*storage[index].heap_index)
	if healthChecks && heapIndex != index+1 {
		panic("heap invariant violated")
	}
	value := storage[index]
	if healthChecks {
		*storage[index].heap_index = 0
		storage[index] = pair[T]{nil, nil}
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
	h.moveUp(h.storage, index, value)
	return true
}

func (h *IntrusiveHeapAry[T]) moveUp(storage []pair[T], index uint, value pair[T]) {
	for index > 0 {
		parent := parentIndex(index)
		if h.pred(h.storage[parent].ptr, value.ptr) {
			break
		}
		tmp := moveOut(storage, parent)
		moveIn(storage, index, tmp)
		index = parent
	}
	moveIn(storage, index, value)
	h.checkHeap()
}

func (h *IntrusiveHeapAry[T]) Erase(node *T, heap_index *int) bool {
	if *heap_index == 0 {
		return false
	}
	index := uint(*heap_index) - 1
	erased := moveOut(h.storage, index)
	if erased != (pair[T]{node, heap_index}) {
		// this is user's invariant, we want to keep it to debug business logic
		panic("heap invariant violated")
	}
	*erased.heap_index = 0

	if index == uint(len(h.storage))-1 {
		h.storage = h.storage[:index]
		h.checkHeap()
		return true
	}
	length := uint(len(h.storage) - 1)
	value := moveOut(h.storage, length)
	h.storage = h.storage[:length]
	if h.pred(erased.ptr, value.ptr) {
		h.moveDown(h.storage, index, length, value)
	} else {
		h.moveUp(h.storage, index, value)
	}
	h.checkHeap()
	return true
}

func (h *IntrusiveHeapAry[T]) PopFront() {
	erased := moveOut(h.storage, 0)
	*erased.heap_index = 0
	if len(h.storage) == 1 {
		h.storage = h.storage[:0]
		h.checkHeap()
		return
	}

	length := uint(len(h.storage) - 1)
	value := moveOut(h.storage, length)
	h.storage = h.storage[:length]
	h.moveDown(h.storage, 0, length, value)
}

func (h *IntrusiveHeapAry[T]) moveDown(storage []pair[T], index uint, length uint, value pair[T]) {
	for {
		lastChild := lastChildIndex(index)
		firstChild := lastChild - mult + 1
		if lastChild < length {
			largestChild := h.largestChildFullRec(mult, firstChild)
			if h.pred(value.ptr, h.storage[largestChild].ptr) {
				break
			}
			tmp := moveOut(h.storage, largestChild)
			moveIn(h.storage, index, tmp)
			index = largestChild
		} else if firstChild < length {
			largestChild := h.largestChildPartialRec(mult, firstChild, length-firstChild)
			if !h.pred(value.ptr, h.storage[largestChild].ptr) {
				tmp := moveOut(h.storage, largestChild)
				moveIn(h.storage, index, tmp)
				index = largestChild
			}
			break
		} else {
			break
		}
	}
	moveIn(h.storage, index, value)
	h.checkHeap()
}

//func (h *IntrusiveHeapAry[T]) popBackToIndex(ind int) {
//	h.storage[ind] = h.storage[len(h.storage)-1]
//	h.storage[len(h.storage)-1] = pair[T]{nil, nil} // do not leave aliases
//	h.storage = h.storage[:len(h.storage)-1]
//}

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
		half := multArg / 2
		firstHalfLargest := h.largestChildFullRec(half, firstChild)
		secondHalfLargest := h.largestChildFullRec(multArg-half, firstChild+half)
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
		switch numChildren {
		case 1:
			return firstChild
		case 2:
			return firstChild + bool2uint(!h.pred(h.storage[firstChild].ptr, h.storage[firstChild+1].ptr))
		case 3:
			largest := firstChild + bool2uint(!h.pred(h.storage[firstChild].ptr, h.storage[firstChild+1].ptr))
			if !h.pred(h.storage[largest].ptr, h.storage[firstChild+2].ptr) {
				return firstChild + 2
			}
			return largest
		case 4:
			{
				largestFirstHalf := firstChild + bool2uint(!h.pred(h.storage[firstChild].ptr, h.storage[firstChild+1].ptr))
				largestSecondHalf := firstChild + 2 + bool2uint(!h.pred(h.storage[firstChild+2].ptr, h.storage[firstChild+3].ptr))
				if !h.pred(h.storage[largestFirstHalf].ptr, h.storage[largestSecondHalf].ptr) {
					return largestSecondHalf
				}
				return largestFirstHalf
			}
		default:
			half := numChildren / 2
			firstHalfLargest := h.largestChildFullRec(half, firstChild)
			secondHalfLargest := h.largestChildPartialRec(numChildren-half+1, firstChild+half, numChildren-half)
			if !h.pred(h.storage[firstHalfLargest].ptr, h.storage[secondHalfLargest].ptr) {
				return secondHalfLargest
			}
			return firstHalfLargest
		}
	}
}
