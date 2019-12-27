package dns

import (
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestToken(t *testing.T) {
	input := `
@ 600 IN SOA ns1 dns\.admin (
 	1234	; serial
	10800	; refresh
	10800	; retry
	604800	; expire
	3600 )	; minimum
 NS ns1
 NS ns2
textrr TXT "a quoted string"
       TXT "a string with \"quotes\" in it"
       TXT "( parens ) ; comment"

`
	tokens := []string{
		"@",
		"600",
		"IN",
		"SOA",
		"ns1",
		"dns\000admin",
		"1234",
		"10800",
		"10800",
		"604800",
		"3600",
		"",
		"NS",
		"ns1",
		"",
		"NS",
		"ns2",
		"textrr",
		"TXT",
		"a quoted string",
		"",
		"TXT",
		`a string with "quotes" in it`,
		"",
		"TXT",
		`( parens ) ; comment`,
	}
	parsed := []string{}

	name, err := NameWithString("tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}
	r := strings.NewReader(input)
	c := NewTextReader(r, name)

	for err = c.startLine(); err == nil; err = c.startLine() {
		for {
			token, err := c.token(true)
			eof := errors.Is(err, io.EOF)

			if err != nil && !eof {
				t.Fatal(err)
			}
			if eof {
				break
			} else {
				parsed = append(parsed, token)
			}
		}
	}
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tokens, parsed) {
		n := len(tokens)
		if len(parsed) > n {
			n = len(parsed)
		}
		for i := 0; i < n; i++ {
			var s1, s2 string
			if i < len(tokens) {
				s1 = tokens[i]
			}
			if i < len(parsed) {
				s2 = parsed[i]
			}
			if s1 != s2 {
				t.Errorf("index %d: expect '%s', got '%s'", i, s1, s2)
			}
		}
		t.Fatalf("expected %+v, got %+v", tokens, parsed)
	}
}

func TestTextName(t *testing.T) {
	input := "ns1 ns1.example.com. record.zone with\\.dot"
	origin, err := NameWithString("tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}
	c := NewTextReader(strings.NewReader(input), origin)
	if err := c.startLine(); err != nil {
		t.Fatal(err)
	}

	names := make([]Name, 4)
	for i := 0; i < 4; i++ {
		var err error
		if names[i], err = c.getName(false); err != nil {
			t.Fatalf("error parsing name %d: %v", i, err)
		}
		t.Log(names[i])
	}
}

func TestTextRecord(t *testing.T) {
	input := `
@ 600 IN SOA ns1 dns\.admin (
 	1234	; serial
	10800	; refresh
	10800	; retry
	604800	; expire
	3600 )	; minimum
`
	origin, err := NameWithString("tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}
	c := NewTextReader(strings.NewReader(input), origin)

	r := &Record{}
	if err := c.Decode(r); err != nil {
		t.Fatal(err)
	}

	mname, err := NameWithString("ns1.tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}
	rname, err := NameWithString("dns\000admin.tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}

	soa := &Record{
		RecordHeader: RecordHeader{
			Name:  origin,
			Class: INClass,
			Type:  SOAType,
			TTL:   600 * time.Second,
		},
		RecordData: &SOARecord{
			MName:   mname,
			RName:   rname,
			Serial:  1234,
			Refresh: 10800 * time.Second,
			Retry:   10800 * time.Second,
			Expire:  604800 * time.Second,
			Minimum: 3600 * time.Second,
		},
	}

	if !reflect.DeepEqual(*r, *soa) {
		t.Fatalf("parsed %+v, expected %+v", *r, *soa)
	}

	output := &strings.Builder{}
	c = NewTextWriter(output)
	if err := c.Encode(r); err != nil {
		t.Fatal(err)
	}

	t.Logf("%s", output.String())

	c = NewTextReader(strings.NewReader(output.String()), origin)
	r2 := &Record{}
	if err := c.Decode(r2); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(*r, *r2) {
		t.Fatalf("parsed %+v, expected %+v", *r2, *r)
	}

}

func TestTextBitmap(t *testing.T) {
	types := []RRType{1, 2, 3, 20, 21}
	var bits Bitmap

	for _, rt := range types {
		bits.Set(rt)
	}

	s := &strings.Builder{}
	c := NewTextWriter(s)

	if err := c.Encode(bits); err != nil {
		t.Fatal(err)
	}

	t.Log(s.String())

	c = NewTextReader(strings.NewReader(s.String()), nil)

	if err := c.Decode(&bits); err != nil {
		t.Fatal(err)
	}

	rt := InvalidType
	for i := 0; ; i++ {
		rt = bits.Next(rt)
		if rt == InvalidType {
			break
		}

		if types[i] != rt {
			t.Fatalf("expected %v, got %v at sequence %d", types[i], rt, i)
		}
	}
}

func TestTextSlice(t *testing.T) {
	origin, err := NameWithString("tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}

	name, err := NameWithString("text.tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}

	txt := &Record{
		RecordHeader: RecordHeader{
			Name:  name,
			TTL:   10 * time.Second,
			Class: INClass,
		},
		RecordData: &TXTRecord{
			Text: []string{"one", "two", "three"},
		},
	}

	output := &strings.Builder{}
	w := NewTextWriter(output)

	if err := w.Encode(txt); err != nil {
		t.Fatal(err)
	}

	t.Log(output)

	rec := &Record{}
	r := NewTextReader(strings.NewReader(output.String()), origin)

	if err := r.Decode(rec); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(txt.RecordData, rec.RecordData) {
		t.Fatalf("expected %+v, got %+v", txt.RecordData, rec.RecordData)
	}

	t.Log(rec)
}

func TestRawRecord(t *testing.T) {
	rec := &Record{}
	r := NewTextReader(strings.NewReader("ns1.tessier-ashpool.net 300 CLASS1 TYPE1 \\# 4 01020304\n"), nil)
	if err := r.Decode(rec); err != nil {
		t.Fatal(err)
	}
	arec, ok := rec.RecordData.(*ARecord)
	if !ok {
		t.Fatalf("expected ARecord, got %T", rec.RecordData)
	}
	if !arec.IP().Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("expected 1.2.3.4, got %v", arec.IP())
	}
	t.Log(rec)
}

func TestOrigin(t *testing.T) {
	input := `
$ORIGIN tessier-ashpool.net
@	300 IN NS ns1
`
	r := NewTextReader(strings.NewReader(input), nil)
	rec := &Record{}
	if err := r.Decode(rec); err != nil {
		t.Fatal(err)
	}
	name, err := NameWithString("tessier-ashpool.net")
	if err != nil {
		t.Fatal(err)
	}
	if !rec.RecordHeader.Name.Equal(name) {
		t.Fatalf("expected %v, got %v", name, rec.RecordHeader.Name)
	}
	nsrec, ok := rec.RecordData.(*NSRecord)
	if !ok {
		t.Fatalf("expected NS record, got %T", rec.RecordData)
	}
	if !nsrec.Name.HasSuffix(name) {
		t.Fatalf("%v does not end with %v", nsrec.Name, name)
	}
}
