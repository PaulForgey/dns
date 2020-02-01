package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

var ErrStringTooLong = errors.New("string longer than 255 octets")
var ErrBadRCode = errors.New("extended RCode with non-EDNS message")

// a Compressor type maps packet offsets at which a complete Name appears
type Compressor map[int]Name

// The WireCodec type encodes and decodes in DNS wire format.
// A WireCodec will never return items holding slices refering to its original buffer, so the original buffer may be safely
// reused. Any verbatim byte sequences will be copied.
type WireCodec struct {
	nc     Compressor
	offset int
	data   []byte
	mdns   bool
}

// a Truncated type is returned from any Encode method which runs out of buffer space. The contents of the buffer
// are invalid at this point.
type Truncated struct {
	err       error
	At, Total int
	Section   int // 0-3 q, an, ns, ar
}

func (e *Truncated) Unwrap() error {
	return e.err
}

func (e *Truncated) Error() string {
	sections := []string{"question", "answer", "authority", "additional"}
	return fmt.Sprintf("overflowed after %d of %d in %s", e.At, e.Total, sections[e.Section])
}

// NewWireCodec creates a new wire codec with the given buffer, either for reading or writing
func NewWireCodec(data []byte) *WireCodec {
	return &WireCodec{
		nc:     make(Compressor),
		offset: 0,
		data:   data,
	}
}

// NewWireCodecNoCompression is like NewWireCodec, but disables the name compressor
func NewWireCodecNoCompression(data []byte) *WireCodec {
	return &WireCodec{
		nc:     nil,
		data:   data,
		offset: 0,
	}
}

// does nothing
// XXX could attach a logger
func (w *WireCodec) Debug(_ string) {}

// MDNS sets MDNS specific wire decoding
func (w *WireCodec) MDNS() {
	w.mdns = true
}

// Reset resets the codec with the given buffer slice, resetting offset to 0 and emptying the name compressor
func (w *WireCodec) Reset(data []byte) {
	w.data = data
	w.offset = 0
	if w.nc != nil {
		for k, _ := range w.nc {
			delete(w.nc, k)
		}
	}
}

// Offset returns the current offset into the given buffer. After writing a complete message, this value is the length.
func (w *WireCodec) Offset() int { return w.offset }

// Split returns a new WireCodec instance containing the buffer at its current position of the specified length.
// length bytes are consumed from w.
func (w *WireCodec) Split(length int) (*WireCodec, error) {
	buffer, err := w.buffer(length)
	if err != nil {
		return nil, err
	}
	return &WireCodec{
		nc:     w.nc,
		data:   buffer,
		offset: w.offset - length,
	}, nil
}

func (w *WireCodec) getByte() (byte, error) {
	if len(w.data) < 1 {
		return 0, io.ErrUnexpectedEOF
	}
	b := w.data[0]
	w.data = w.data[1:]
	w.offset++
	return b, nil
}

func (w *WireCodec) buffer(n int) ([]byte, error) {
	if n > len(w.data) {
		return nil, io.ErrUnexpectedEOF
	}
	w.offset += n
	buf := w.data[:n]
	w.data = w.data[n:]
	return buf, nil
}

func (w *WireCodec) variable() []byte {
	end := len(w.data)
	data := w.data[:end]
	w.data = w.data[end:]
	w.offset += end

	return data
}

func (w *WireCodec) putName(n Name) error {
	label := n.Label()
	if label == nil {
		buf, err := w.buffer(1)
		if err != nil {
			return err
		}
		buf[0] = 0
		return nil
	}

	for ptr, entry := range w.nc {
		if entry.Equal(n) {
			buf, err := w.buffer(2)
			if err != nil {
				return err
			}
			buf[0] = byte(ptr>>8) | 0xc0
			buf[1] = byte(ptr & 0xff)
			return nil
		}
	}

	if w.nc != nil {
		w.nc[w.offset] = n
	}

	buf, err := w.buffer(len(label.data))
	if err != nil {
		return err
	}
	copy(buf, label.data)

	return w.putName(n.Suffix())
}

func (w *WireCodec) putRecord(r *Record) error {
	if err := r.H.MarshalCodec(w); err != nil {
		return err
	}

	lw, err := w.Split(2) // length field
	if err != nil {
		return err
	}

	start := w.Offset()

	if r.D != nil {
		nc := w.nc
		// do not compress unicast SRV
		if !w.mdns && r.Type() == SRVType {
			w.nc = nil
		}
		err = r.D.MarshalCodec(w)
		w.nc = nc
		if err != nil {
			return err
		}
	}

	length := w.Offset() - start
	if err := lw.Encode(uint16(length)); err != nil {
		return err
	}

	return nil
}

func (w *WireCodec) putMessage(m *Message) error {
	var status uint16

	if m.QR {
		status |= 0x8000
	}
	status |= (uint16(m.Opcode) & 0xf) << 11
	if m.AA {
		status |= 0x0400
	}
	if m.TC {
		status |= 0x0200
	}
	if m.RD {
		status |= 0x0100
	}
	if m.RA {
		status |= 0x0080
	}
	status |= uint16(m.RCode) & 0xf

	if m.RCode > 0xf && m.EDNS == nil {
		return ErrBadRCode
	}

	adLen := uint16(len(m.Additional))
	if m.EDNS != nil {
		m.EDNS.H.(*EDNSHeader).SetExtRCode(uint8(m.RCode&0xff0) >> 4)
		adLen++
	}

	if err := EncodeSequence(
		w,
		m.ID,
		status,
		uint16(len(m.Questions)),
		uint16(len(m.Answers)),
		uint16(len(m.Authority)),
		adLen,
	); err != nil {
		return err
	}

	for i, r := range m.Questions {
		if err := w.Encode(r); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return &Truncated{err: err, At: i, Total: len(m.Questions), Section: 0}
			}
			return err
		}
	}
	for i, r := range m.Answers {
		if err := w.Encode(r); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return &Truncated{err: err, At: i, Total: len(m.Answers), Section: 1}
			}
			return err
		}
	}
	for i, r := range m.Authority {
		if err := w.Encode(r); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return &Truncated{err: err, At: i, Total: len(m.Authority), Section: 2}
			}
			return err
		}
	}
	if m.EDNS != nil {
		if err := w.Encode(m.EDNS); err != nil {
			return err
		}
	}
	for i, r := range m.Additional {
		if err := w.Encode(r); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return &Truncated{err: err, At: i, Total: len(m.Additional), Section: 3}
			}
			return err
		}
	}

	return nil
}

func (w *WireCodec) Encode(i interface{}) error {
	switch t := i.(type) {
	case byte:
		buf, err := w.buffer(1)
		if err != nil {
			return err
		}
		buf[0] = t

	case uint16:
		buf, err := w.buffer(2)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint16(buf, t)

	case uint32:
		buf, err := w.buffer(4)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint32(buf, t)

	case time.Duration:
		buf, err := w.buffer(4)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint32(buf, uint32(t/time.Second))

	case [4]byte:
		buf, err := w.buffer(4)
		if err != nil {
			return err
		}
		copy(buf, t[:])

	case [16]byte:
		buf, err := w.buffer(16)
		if err != nil {
			return err
		}
		copy(buf, t[:])

	case []byte:
		buf, err := w.buffer(len(t))
		if err != nil {
			return err
		}
		copy(buf, t)

	case []string, string:
		var strings []string

		switch t := i.(type) {
		case string:
			strings = []string{t}
		case []string:
			strings = t
		}

		for _, s := range strings {
			if len(s) > 255 {
				return ErrStringTooLong
			}
			buf, err := w.buffer(len(s) + 1)
			if err != nil {
				return err
			}
			buf[0] = byte(len(s))
			copy(buf[1:], []byte(s))
		}

	case Name:
		if err := w.putName(t); err != nil {
			return err
		}

	case *Record:
		if err := w.putRecord(t); err != nil {
			return err
		}

	case *Message:
		if err := w.putMessage(t); err != nil {
			return err
		}

	case Encoder:
		if err := t.MarshalCodec(w); err != nil {
			return err
		}

	default:
		panic(fmt.Sprintf("unsupported type %T", t))
	}

	return nil
}

func (w *WireCodec) getName() (Name, error) {
	offset := w.offset
	b1, err := w.getByte()
	if err != nil {
		return nil, err
	}

	if (b1 & 0xc0) == 0xc0 {
		if w.nc == nil {
			return nil, fmt.Errorf("%w: compressed name with compression disabled", FormError)
		}

		b2, err := w.getByte()
		if err != nil {
			return nil, err
		}

		noffset := int(b1&0x3f)<<8 + int(b2)
		name, ok := w.nc[noffset]
		if !ok {
			return nil, fmt.Errorf("%w: bad name compression pointer 0x%04x at offset 0x%04x",
				FormError, noffset, offset)
		}
		w.nc[offset] = name
		return name, nil
	}

	if (b1 & 0xc0) != 0 {
		return nil, fmt.Errorf("%w: unknown label type %x", FormError, b1&0xc0)
	}

	if b1 == 0 {
		w.nc[offset] = nil
		return nil, nil
	}

	buf, err := w.buffer(int(b1))
	if err != nil {
		return nil, err
	}
	label, err := LabelWithString(string(buf))
	if err != nil {
		return nil, err
	}
	name := NameWithLabel(label)
	suffix, err := w.getName()
	if err != nil {
		return nil, err
	}
	name = name.Append(suffix)

	if w.nc != nil {
		w.nc[offset] = name
	}
	return name, nil
}

func (w *WireCodec) getRecord(r *Record) error {
	var d HeaderData

	if err := d.UnmarshalCodec(w); err != nil {
		return err
	}

	if d.Type() == EDNSType {
		r.H = EDNSHeaderFromData(&d)
	} else if w.mdns {
		r.H = MDNSHeaderFromData(&d)
	} else {
		r.H = HeaderFromData(&d)
	}

	var length uint16
	if err := w.Decode(&length); err != nil {
		return err
	}

	// RFC 2136 cases of RecordData being purposfully nil
	if length == 0 && (r.H.Class() == AnyClass || r.H.Class() == NoneClass) {
		r.D = nil
	} else {
		dc, err := w.Split(int(length))
		if err != nil {
			return err
		}

		r.D = RecordFromType(r.H.Type())
		return dc.Decode(r.D)
	}

	return nil
}

func (w *WireCodec) getMessage(m *Message) error {
	var status, qdcount, ancount, nscount, arcount uint16

	if err := DecodeSequence(
		w,
		&m.ID,
		&status,
		&qdcount,
		&ancount,
		&nscount,
		&arcount,
	); err != nil {
		return err
	}

	m.QR, m.AA, m.TC, m.RD, m.RA =
		(status&0x8000) != 0,
		(status&0x0400) != 0,
		(status&0x0200) != 0,
		(status&0x0100) != 0,
		(status&0x0080) != 0
	m.Opcode = Opcode((status & 0x7800) >> 11)
	m.RCode = RCode(status & 0xf)

	m.Questions = make([]Question, int(qdcount))
	m.Answers = make([]*Record, int(ancount))
	m.Authority = make([]*Record, int(nscount))
	m.Additional = make([]*Record, 0, int(arcount))

	for i := range m.Questions {
		q := &QuestionData{}
		if err := w.Decode(q); err != nil {
			return err
		}
		if w.mdns {
			m.Questions[i] = MDNSQuestionFromData(q)
		} else {
			m.Questions[i] = DNSQuestionFromData(q)
		}
	}
	for i := range m.Answers {
		r := &Record{}
		if err := w.Decode(r); err != nil {
			return err
		}
		m.Answers[i] = r
	}
	for i := range m.Authority {
		r := &Record{}
		if err := w.Decode(r); err != nil {
			return err
		}
		m.Authority[i] = r
	}
	for i := uint16(0); i < arcount; i++ {
		r := &Record{}
		if err := w.Decode(r); err != nil {
			return err
		}

		if r.Type() == EDNSType {
			// special case this one.
			// It is not appropriate to let it deserialize as its own pseudo record type like others
			if m.EDNS != nil {
				return fmt.Errorf("%w: multiple EDNS records", FormError)
			}
			m.EDNS = r
		} else {
			m.Additional = append(m.Additional, r)
		}
	}

	if m.EDNS != nil {
		eh := m.EDNS.H.(*EDNSHeader)
		if eh.Version() > 0 {
			return fmt.Errorf("%w: highest supported version is 0", BadVersion)
		}
		m.RCode |= RCode(eh.ExtRCode()) << 4
	}

	return nil
}

func (w *WireCodec) getString() (string, error) {
	buf, err := w.buffer(1)
	if err != nil {
		return "", err
	}
	size := buf[0]
	buf, err = w.buffer(int(size))
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func (w *WireCodec) Decode(i interface{}) error {
	switch t := i.(type) {
	case *byte:
		buf, err := w.buffer(1)
		if err != nil {
			return err
		}
		*t = buf[0]

	case *uint16:
		buf, err := w.buffer(2)
		if err != nil {
			return err
		}
		*t = binary.BigEndian.Uint16(buf)

	case *uint32:
		buf, err := w.buffer(4)
		if err != nil {
			return err
		}
		*t = binary.BigEndian.Uint32(buf)

	case *time.Duration:
		buf, err := w.buffer(4)
		if err != nil {
			return err
		}
		*t = time.Duration(binary.BigEndian.Uint32(buf)) * time.Second

	case *[4]byte:
		buf, err := w.buffer(4)
		if err != nil {
			return err
		}
		copy((*t)[:], buf)

	case *[16]byte:
		buf, err := w.buffer(16)
		if err != nil {
			return err
		}
		copy((*t)[:], buf)

	case *[]byte:
		var buf []byte
		if len(*t) == 0 {
			buf = w.variable()
		} else {
			var err error
			buf, err = w.buffer(len(*t))
			if err != nil {
				return err
			}
		}
		if len(*t) == 0 {
			*t = make([]byte, len(buf))
		}
		copy(*t, buf)

	case *[]string:
		var strings []string
		for len(w.data) > 0 {
			s, err := w.getString()
			if err != nil {
				return err
			}
			strings = append(strings, s)
		}
		*t = strings

	case *string:
		s, err := w.getString()
		if err != nil {
			return err
		}
		*t = s

	case *Name:
		name, err := w.getName()
		if err != nil {
			return err
		}
		*t = name

	case *Record:
		if err := w.getRecord(t); err != nil {
			return err
		}

	case *Message:
		if err := w.getMessage(t); err != nil {
			return err
		}

	case Decoder:
		if err := t.UnmarshalCodec(w); err != nil {
			return err
		}

	default:
		panic(fmt.Sprintf("unsupported type %T", t))

	}

	return nil
}
