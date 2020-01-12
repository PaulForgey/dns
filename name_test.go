package dns

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func dump(bytes []byte) {
	fmt.Println(hex.Dump(bytes))
}

func TestLabelIntern(t *testing.T) {
	labels := make([]*Label, 4)
	strings := []string{"tessier-ashpool", "tessier-ashpool", "shoesinonehour", "Tessier-Ashpool"}

	for i := range labels {
		var err error
		labels[i], err = LabelWithString(strings[i])
		if err != nil {
			t.Fatalf("%s: %v", strings[i], err)
		}
	}

	if labels[0] != labels[1] {
		t.Fatalf("%s and %s should have same pointers: %p, %p",
			strings[0], strings[1],
			labels[0], labels[1],
		)
	}
	if labels[0] == labels[2] {
		t.Fatalf("%s and %s should not have same pointer: %p",
			strings[0], strings[2],
			labels[0],
		)
	}
	if labels[0] == labels[3] {
		t.Fatalf("%s and %s should be different instances: %p, %p",
			strings[0], strings[3],
			labels[0], labels[3],
		)
	}
	t.Logf("case preserved instances %v and %v", labels[0], labels[3])
	if !labels[0].Equal(labels[3]) {
		t.Fatalf("%v and %v should be Equal", labels[0], labels[3])
	}
}

func TestLable(t *testing.T) {
	l, err := LabelWithString("tessier-ashpool")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("l = %v", l)

	l2, err := LabelWithString("Tessier-Ashpool")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("l2 = %v", l2)

	equal := l.Equal(l2)
	if !equal {
		t.Fatalf("%v != %v", l, l2)
	}

	equal = l.String() == "tessier-ashpool"
	if !equal {
		t.Fatalf("unexpected string %s", l.String())
	}
}

func TestName(t *testing.T) {
	data := make([]byte, 4096)
	c := NewWireCodec(data)

	var err error

	textNames := []string{
		"ns1.tessier-ashpool.net",
		"ns2.tessier-ashpool.net",
		"Tessier-Ashpool.net",
		"tessier-ashpool.net",
	}
	names := make([]Name, len(textNames))
	for i, n := range textNames {
		names[i], err = NameWithString(n)
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Logf("names=%+v", names)

	if !names[0].HasSuffix(names[3]) {
		t.Fatalf("%v should have suffix %v", names[0], names[3])
	}
	if names[3].HasSuffix(names[0]) {
		t.Fatalf("%v should not have suffix %v", names[3], names[0])
	}

	for _, n := range names {
		if err := c.Encode(n); err != nil {
			t.Fatal(err)
		}
		t.Logf("encoded %v", n)
	}

	data = data[:c.Offset()]
	dump(data)
	c = NewWireCodec(data)

	dnames := make([]Name, 4)
	for i := range dnames {
		if err := c.Decode(&dnames[i]); err != nil {
			t.Fatal(err)
		}
		if !dnames[i].Equal(names[i]) {
			t.Fatalf("decoded %v != %v", dnames[i], names[i])
		}
		t.Logf("decoded %v", dnames[i])
	}
}
