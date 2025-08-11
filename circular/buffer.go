package circular

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
		capacity = 1
	}
	for capacity < newCapacity {
		capacity *= 2
	}
	s1, s2 := s.Slices()
	elements := make([]T, capacity) // size will forever be equal to capacity
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
	if newCapacity > len(s.elements) { // fits perfectly, do nothing
		s.reserve(newCapacity)
	}
}

func (s *Buffer[T]) PushBack(element T) {
	capacity := len(s.elements)
	if s.Len() == capacity {
		s.reserve(max(4, capacity*2))
	}
	s.elements[s.write_pos&s.mask()] = element
	s.write_pos++
}

func (s *Buffer[T]) Front() T {
	if s.write_pos == s.read_pos {
		panic("empty circular buffer")
	}
	return s.elements[s.read_pos&s.mask()]
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

func (s *Buffer[T]) PopFront() T {
	if s.write_pos == s.read_pos {
		panic("empty circular buffer")
	}
	offset := s.read_pos & s.mask()
	element := s.elements[offset]
	var empty T
	s.elements[offset] = empty // do not have dangling references in unused parts of buffer
	s.read_pos++
	return element
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
