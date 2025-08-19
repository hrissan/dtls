package circular

// like BufferExt, but with external storage (waiting for generics over arrays)

type BufferExt[T any] struct {
	read_pos  uint // uint because we rely on integer overflow
	write_pos uint
}

func (s *BufferExt[T]) Len() int {
	return int(s.write_pos - s.read_pos) // diff will always fit int and be >= 0
}

func (s *BufferExt[T]) Cap(elements []T) int {
	return len(elements)
}

func (s *BufferExt[T]) mask(elements []T) uint { return uint(len(elements)) - 1 } // also correct for 0 length

// Two parts of circular buffer
func (s *BufferExt[T]) Slices(elements []T) ([]T, []T) {
	m := s.mask(elements)
	if s.write_pos&^m == s.read_pos&^m {
		return elements[s.read_pos&m : s.write_pos&m], nil
	}
	return elements[s.read_pos&m:], elements[:s.write_pos&m]
}

func (s *BufferExt[T]) PushBack(elements []T, element T) {
	capacity := len(elements)
	if s.Len() == capacity {
		panic("full circular buffer")
	}
	elements[s.write_pos&s.mask(elements)] = element
	s.write_pos++
}

func (s *BufferExt[T]) Front(elements []T) T {
	return *s.FrontRef(elements)
}

func (s *BufferExt[T]) FrontRef(elements []T) *T {
	if s.write_pos == s.read_pos {
		panic("empty circular buffer")
	}
	return &elements[s.read_pos&s.mask(elements)]
}

func (s *BufferExt[T]) Back(elements []T) T {
	return *s.BackRef(elements)
}

func (s *BufferExt[T]) BackRef(elements []T) *T {
	if s.write_pos == s.read_pos {
		panic("empty circular buffer")
	}
	return &elements[(s.write_pos-1)&s.mask(elements)]
}

func (s *BufferExt[T]) Index(elements []T, pos int) T {
	return *s.IndexRef(elements, pos)
}

func (s *BufferExt[T]) IndexRef(elements []T, pos int) *T {
	if pos < 0 {
		panic("circular buffer index < 0")
	}
	if pos >= s.Len() {
		panic("circular buffer index out of range")
	}
	return &elements[(s.read_pos+uint(pos))&s.mask(elements)]
}

func (s *BufferExt[T]) PopFront(elements []T) T {
	t, ok := s.TryPopFront(elements)
	if !ok {
		panic("empty circular buffer")
	}
	return t
}

func (s *BufferExt[T]) TryPopFront(elements []T) (T, bool) {
	var empty T
	if s.write_pos == s.read_pos {
		return empty, false
	}
	offset := s.read_pos & s.mask(elements)
	element := elements[offset]
	elements[offset] = empty // do not have dangling references in unused parts of buffer
	s.read_pos++
	return element, true
}

func (s *BufferExt[T]) Clear(elements []T) {
	var empty T
	s1, s2 := s.Slices(elements)
	for i := range s1 {
		s1[i] = empty
	}
	for i := range s2 {
		s2[i] = empty
	}
	s.read_pos = 0
	s.write_pos = 0
}
