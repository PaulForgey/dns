package dns

import (
	"testing"
)

func TestBitmapType(t *testing.T) {
	var b Bitmap

	expected := []RRType{1, 2, 3, 20, 21, 130, 8192, 16384}

	for _, rt := range expected {
		b.Set(rt)
	}

	rt := InvalidType

	for i := 0; ; i++ {
		rt = b.Next(rt)
		if rt == InvalidType {
			break
		}
		if rt != expected[i] {
			t.Fatalf("expected %v, got %v for sequence %d", expected[i], rt, i)
		}
		if !b.Is(rt) {
			t.Fatalf("Is(%v)==false", rt)
		}
	}
}
