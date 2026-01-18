package antireplay

import (
	"bufio"
	"crypto/rand"
	"testing"
)

func BenchmarkMapFilter(b *testing.B) {
	filter := NewMapFilter(120)
	sample := make([]byte, 16)
	reader := bufio.NewReader(rand.Reader)
	reader.Read(sample)
	b.ResetTimer()
	for range b.N {
		reader.Read(sample)
		filter.Check(sample)
	}
}

func TestMapFilter(t *testing.T) {
	filter := NewMapFilter(120)
	sample := make([]byte, 16)
	rand.Read(sample)
	filter.Check(sample)
	if filter.Check(sample) {
		t.Error("Unexpected true negative")
	}
	sample[0]++
	if !filter.Check(sample) {
		t.Error("Unexpected false positive")
	}
}
