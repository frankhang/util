package arena

// Allocator pre-allocates memory to reduce memory allocation cost.
// It is not thread-safe.
type Allocator interface {
	// Alloc allocates memory with 0 len and capacity cap.
	Alloc(capacity int) []byte

	// AllocWithLen allocates memory with length and capacity.
	AllocWithLen(length int, capacity int) []byte

	// Reset resets arena offset.
	// Make sure all the allocated memory are not used any more.
	Reset()
}

// SimpleAllocator is a simple implementation of ArenaAllocator.
type SimpleAllocator struct {
	arena []byte
	off   int
}

type stdAllocator struct {
}

func (a *stdAllocator) Alloc(capacity int) []byte {
	return make([]byte, 0, capacity)
}

func (a *stdAllocator) AllocWithLen(length int, capacity int) []byte {
	return make([]byte, length, capacity)
}

func (a *stdAllocator) Reset() {
}

var _ Allocator = &stdAllocator{}

// StdAllocator implements Allocator but do not pre-allocate memory.
var StdAllocator = &stdAllocator{}

// NewAllocator creates an Allocator with a specified capacity.
func NewAllocator(capacity int) *SimpleAllocator {
	return &SimpleAllocator{arena: make([]byte, 0, capacity)}
}

// Alloc implements Allocator.AllocBytes interface.
func (s *SimpleAllocator) Alloc(capacity int) []byte {
	if capacity < 0 {
		panic("Alloc capacity is negative")
	}
	if s.off+capacity < cap(s.arena) {
		slice := s.arena[s.off : s.off : s.off+capacity]
		s.off += capacity
		return slice
	}

	return make([]byte, 0, capacity)
}

// AllocWithLen implements Allocator.AllocWithLen interface.
func (s *SimpleAllocator) AllocWithLen(length int, capacity int) []byte {
	if length < 0 {
		panic("Alloc length is negative")
	}
	slice := s.Alloc(capacity)
	return slice[:length:capacity]
}

// Reset implements Allocator.Reset interface.
func (s *SimpleAllocator) Reset() {
	s.off = 0
}
