package dns

import (
	"strings"
)

var labelReplacer = strings.NewReplacer(`.`, `\.`, `\`, `\\`, `"`, `\"`)

// The Label type is a name component, stored in wire format.
type Label struct {
	data []byte
	key  string // cache a comparable key value
}

// The Name type is an array of Label types forming a fully qualified name. An empty name represents the zone '.'.
type Name []*Label

// LabelWithString creates a label from a string. As a special case, any occurance of \000 (zero) is replaced with '.'.
func LabelWithString(s string) (*Label, error) {
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
	return l, nil
}

// Equal returns true if both labels compare equally according to DNS rules.
func (l *Label) Equal(r *Label) bool {
	return l.key == r.key
}

// Less returns true if l < r
func (l *Label) Less(r *Label) bool {
	return l.key < r.key
}

// String returns a string representation of the label, escaping the characters '.' and '\' with a preceding '\'.
func (l *Label) String() string {
	return labelReplacer.Replace(string(l.data[1:]))
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
	ni := len(n) - 1
	ri := len(r) - 1
	for ni >= 0 && ri >= 0 {
		if n[ni].Less(r[ri]) {
			return true
		}
		if !n[ni].Equal(r[ri]) {
			return false
		}
		ni--
		ri--
	}
	if ni < 0 && ri >= 0 {
		return true
	}
	return false
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
		b.WriteRune('.')
	}
	return b.String()
}

// Key returns a value sufficient for use as a key in a map. The returned string is not guaranteed to be printable.
func (n Name) Key() string {
	var key string
	for _, l := range n {
		key += l.key + string(0)
	}
	return key
}

// Len returns the number of labels in a Name.
func (n Name) Len() int {
	return len(n)
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
		n = n.Append(NameWithLabel(label))
	}
	return n, nil
}

// Name returns.. itself. This method exists to easily implement the NameRecordType interface by deriving from Name
func (n Name) Name() Name { return n }

// Copy returns a copy of a name (same labels are still referenced as lables are immutable)
func (n Name) Copy() Name {
	c := make(Name, len(n))
	copy(c, n)
	return c
}

// As a convenience, Name conforms to Encoder and Decoder simplifying records having only a single domain name as rdata.
// The underlying codec better handle Name type, otherwise this could infinitely recurse.
func (n Name) MarshalCodec(c Codec) error    { return c.Encode(n) }
func (n *Name) UnmarshalCodec(c Codec) error { return c.Decode(n) }
