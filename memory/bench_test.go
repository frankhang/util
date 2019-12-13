package memory

import (
	"testing"
)

func BenchmarkMemTotal(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = MemTotal()
	}
}

func BenchmarkMemUsed(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = MemUsed()
	}
}
