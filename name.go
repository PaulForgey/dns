package dns

import (
	"errors"
	"strings"
	"sync"
)

var ErrLabel = errors.New("label too long")
var ErrName = errors.New("name too long")

var labelNames sync.Map

// The Label type is a name component, stored in wire format.
type Label struct {
	data []byte
	key  string // cache a comparable key value
}

// The Name type is an array of Label types forming a fully qualified name. An empty name represents the zone '.'.
type Name []*Label

// LabelWithString creates a label from a string. As a special case, any occurance of \000 (zero) is replaced with '.'.
// The String() method does not return a result which would parse as the same thing in this case
func LabelWithString(s string) (*Label, error) {
	// intern case preserved
	value, ok := labelNames.Load(s)
	if ok {
		return value.(*Label), nil
	}

	n := len(s)
	if n > 63 {
		return nil, ErrLabel
	}
	l := &Label{}
	l.data = make([]byte, n+1)
	l.data[0] = byte(n)
	for i := 0; i < n; i++ {
		b := s[i]
		if b == 0 {
			l.data[i+1] = '.'
		} else {
			l.data[i+1] = byte(b)
		}
	}
	l.key = strings.ToLower(string(l.data[1:]))

	// if we race, faster to throw away our new one than to replace the old one
	value, _ = labelNames.LoadOrStore(s, l)
	return value.(*Label), nil
}

// Equal returns true if both labels compare equally according to DNS rules.
func (l *Label) Equal(r *Label) bool {
	return l == r || l.key == r.key
}

// Less returns true if l < r
func (l *Label) Less(r *Label) bool {
	return l.key < r.key
}

// String returns a string representation of the label
func (l *Label) String() string {
	return string(l.data[1:])
}

// Length returns the wire length of the label
func (l *Label) Len() int {
	return len(l.data)
}

// Equal returns true if both Names are equal according to DNS rules.
func (n Name) Equal(r Name) bool {
	if len(n) != len(r) {
		return false
	}
	for i := range n {
		if !n[i].Equal(r[i]) {
			return false
		}
	}

	return true
}

// Less returns true if n < r.
func (n Name) Less(r Name) bool {
	c := len(n) - len(r)
	var j int
	if c < 0 {
		j = len(n)
	} else {
		j = len(r)
	}
	for i := 0; i < j; i++ {
		if n[i].Less(r[i]) {
			return true
		}
		if !n[i].Equal(r[i]) {
			return false
		}
	}
	return c < 0
}

// HasSuffix returns true if n ends with r (or if they are equal). HasSuffix will always return true if r is an empty name.
func (n Name) HasSuffix(r Name) bool {
	offset := len(n) - len(r)
	if offset < 0 {
		return false
	}
	return n[offset:].Equal(r)
}

// Prefix returns a new Name containing the label sequence up to suffix. If the name does not end with suffix, the original
// name is returned.
func (n Name) Prefix(suffix Name) Name {
	offset := len(n) - len(suffix)
	if offset < 0 {
		return n
	}
	if n[offset:].Equal(suffix) {
		return n[:offset]
	}
	return n
}

func (n Name) String() string {
	if len(n) == 0 {
		return "."
	}
	var b strings.Builder
	for _, l := range n {
		b.WriteString(l.String())
		b.WriteByte('.')
	}
	return b.String()
}

// Key returns a value sufficient for use as a key in a map. The returned string is not printable.
func (n Name) Key() string {
	var key strings.Builder
	for _, l := range n {
		key.WriteString(l.key)
		key.WriteByte(0)
	}
	return key.String()
}

// Len returns the uncompressed wire length of the name
func (n Name) Len() int {
	var length int
	for _, l := range n {
		length += l.Len()
	}
	return length
}

// Append returns a new name of n.a
func (n Name) Append(a Name) Name {
	return append(n, a...)
}

// Suffix returns a new Name containing all but the first label. If the Name is empty or has only one label, and empty
// Name is returned.
func (n Name) Suffix() Name {
	if len(n) > 0 {
		return n[1:]
	}
	return nil
}

// Label returns the first label in a Name.
func (n Name) Label() *Label {
	if len(n) > 0 {
		return n[0]
	}
	return nil
}

// NameWithLabel creates a new Name containing the given Label.
func NameWithLabel(l *Label) Name {
	return []*Label{l}
}

// NameWithString creates a new Name from a string in dot notation. To include a label containing the '.' character, use the
// \000 (zero) character instead. The resulting Labels will contain '.' characters in their place.
func NameWithString(s string) (Name, error) {
	var length int

	labels := strings.Split(s, ".")
	n := Name{}
	for _, l := range labels {
		if l == "" {
			break
		}
		label, err := LabelWithString(l)
		if err != nil {
			return n, err
		}
		length += label.Len()
		if length > 255 {
			return n, ErrName
		}
		n = n.Append(NameWithLabel(label))
	}
	return n, nil
}

// RName returns.. itself. This method exists to easily implement the NameRecordType interface by deriving from Name
func (n Name) RName() Name { return n }

// As a convenience, Name conforms to Encoder and Decoder simplifying records having only a single domain name as rdata.
// The underlying codec better handle Name type, otherwise this could infinitely recurse.
func (n Name) MarshalCodec(c Codec) error    { return c.Encode(n) }
func (n *Name) UnmarshalCodec(c Codec) error { return c.Decode(n) }
