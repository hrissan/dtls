// Copyright (c) 2025, Grigory Buteyko aka Hrissan
// Licensed under the MIT License. See LICENSE for details.

package circular

const minCapacity = 4 // reduce tiny fragments

type Buffer[T any] struct {
	elements  []T  // length == capacity == 2^x
	read_pos  uint // uint because we rely on integer overflow
	write_pos uint
}

func (s *Buffer[T]) Len() int {
	return int(s.write_pos - s.read_pos) // diff will always fit int and be >= 0
}

func (s *Buffer[T]) Cap() int {
	return len(s.elements)
}

func (s *Buffer[T]) mask() uint { return uint(len(s.elements)) - 1 } // also correct for 0 length

// Two parts of circular buffer
func (s *Buffer[T]) Slices() ([]T, []T) {
	m := s.mask()
	if s.write_pos&^m == s.read_pos&^m {
		return s.elements[s.read_pos&m : s.write_pos&m], nil
	}
	return s.elements[s.read_pos&m:], s.elements[:s.write_pos&m]
}

func (s *Buffer[T]) reserve(newCapacity int) {
	capacity := len(s.elements)
	if capacity == 0 {
		capacity = minCapacity
	}
	for capacity < newCapacity {
		capacity *= 2
	}
	s1, s2 := s.Slices()
	elements := make([]T, capacity) // lem() will forever be equal to cap()
	off := copy(elements, s1)
	off += copy(elements[off:], s2)
	if off != len(s1)+len(s2) {
		panic("circular buffer invariant violated in Reserve")
	}
	s.read_pos = 0
	s.write_pos = uint(off)
	s.elements = elements
}

func (s *Buffer[T]) Reserve(newCapacity int) {
	if newCapacity > len(s.elements) { // if fits perfectly, do nothing
		s.reserve(newCapacity)
	}
}

// TODO - fuzz all new methods
func (s *Buffer[T]) PushFront(element T) {
	capacity := len(s.elements)
	if s.Len() == capacity {
		s.reserve(capacity + 1)
	}
	s.read_pos--
	s.elements[s.read_pos&s.mask()] = element
}

func (s *Buffer[T]) Front() T {
	return *s.FrontRef()
}

func (s *Buffer[T]) FrontRef() *T {
	if s.write_pos == s.read_pos {
		panic("empty circular buffer")
	}
	return &s.elements[s.read_pos&s.mask()]
}

func (s *Buffer[T]) PopFront() T {
	t, ok := s.TryPopFront()
	if !ok {
		panic("empty circular buffer")
	}
	return t
}

func (s *Buffer[T]) TryPopFront() (T, bool) {
	var empty T
	if s.write_pos == s.read_pos {
		return empty, false
	}
	offset := s.read_pos & s.mask()
	element := s.elements[offset]
	s.elements[offset] = empty // do not have dangling references in unused parts of buffer
	s.read_pos++
	return element, true
}

func (s *Buffer[T]) PushBack(element T) {
	capacity := len(s.elements)
	if s.Len() == capacity {
		s.reserve(capacity + 1)
	}
	s.elements[s.write_pos&s.mask()] = element
	s.write_pos++
}

func (s *Buffer[T]) Back() T {
	return *s.BackRef()
}

func (s *Buffer[T]) BackRef() *T {
	if s.write_pos == s.read_pos {
		panic("empty circular buffer")
	}
	return &s.elements[(s.write_pos-1)&s.mask()]
}

func (s *Buffer[T]) PopBack() T {
	t, ok := s.TryPopBack()
	if !ok {
		panic("empty circular buffer")
	}
	return t
}

func (s *Buffer[T]) TryPopBack() (T, bool) {
	var empty T
	if s.write_pos == s.read_pos {
		return empty, false
	}
	s.write_pos--
	offset := s.write_pos & s.mask()
	element := s.elements[offset]
	s.elements[offset] = empty // do not have dangling references in unused parts of buffer
	return element, true
}

func (s *Buffer[T]) Index(pos int) T {
	return *s.IndexRef(pos)
}

func (s *Buffer[T]) IndexRef(pos int) *T {
	if pos < 0 {
		panic("circular buffer index < 0")
	}
	if pos >= s.Len() {
		panic("circular buffer index out of range")
	}
	return &s.elements[(s.read_pos+uint(pos))&s.mask()]
}

func (s *Buffer[T]) Clear() {
	var empty T
	s1, s2 := s.Slices()
	for i := range s1 {
		s1[i] = empty
	}
	for i := range s2 {
		s2[i] = empty
	}
	s.read_pos = 0
	s.write_pos = 0
}

func (s *Buffer[T]) DeepAssign(other Buffer[T]) {
	*s = Buffer[T]{
		elements:  append([]T(nil), other.elements...),
		read_pos:  other.read_pos,
		write_pos: other.write_pos,
	}
}

func (s *Buffer[T]) Swap(other *Buffer[T]) {
	s.elements, other.elements = other.elements, s.elements
	s.write_pos, other.write_pos = other.write_pos, s.write_pos
	s.read_pos, other.read_pos = other.read_pos, s.read_pos
}
