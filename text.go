package dns

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// strings or runes of special meaning
var (
	dot = string(0)
	raw = string(1)
)

var ErrUnexpectedToken = errors.New("unexpected token")

type bufReadCloser struct {
	*bufio.Reader
	f io.Closer
}

func (b *bufReadCloser) Close() error {
	if b.f != nil {
		return b.f.Close()
	}
	return nil
}

type fileReader struct {
	*bufReadCloser
	dir         string
	savedOrigin Name
	prev        *fileReader
}

// A TextCodec type reads and writes records in zone file format
type TextCodec struct {
	r *fileReader
	w io.Writer

	origin  Name
	ttl     time.Duration
	rrclass RRClass

	rname      Name
	line       string
	unbuf      string
	sol, paren bool
	eof        bool
}

// NewTextReader creates TextCodec for reading.
func NewTextReader(r io.Reader, origin Name) *TextCodec {
	fr := &fileReader{
		bufReadCloser: &bufReadCloser{
			Reader: bufio.NewReader(r),
			f:      nil,
		},
	}

	return &TextCodec{
		r:       fr,
		origin:  origin,
		rname:   origin,
		rrclass: INClass,
	}
}

// NewTextFileReader creates a TextCodec for reading from a file.
func NewTextFileReader(filename string, origin Name) (*TextCodec, error) {
	c := &TextCodec{
		origin:  origin,
		rname:   origin,
		rrclass: INClass,
	}

	if err := c.push(filename); err != nil {
		return nil, err
	}

	return c, nil
}

// NewTextWriter creates a TextCodec for writing
func NewTextWriter(w io.Writer) *TextCodec {
	return &TextCodec{
		w: w,
	}
}

// push an included filename
func (c *TextCodec) push(filename string) error {
	var dir, name string

	if c.r == nil {
		dir = path.Dir(filename)
	} else {
		dir = path.Clean(path.Join(c.r.dir, path.Dir(filename)))
	}
	name = path.Join(dir, path.Base(filename))

	f, err := os.Open(name)
	if err != nil {
		return err
	}

	c.r = &fileReader{
		bufReadCloser: &bufReadCloser{
			Reader: bufio.NewReader(f),
			f:      f,
		},
		dir:         dir,
		savedOrigin: c.origin,
		prev:        c.r,
	}
	return nil
}

func (c *TextCodec) pop() error {
	c.r.Close()
	c.origin = c.r.savedOrigin
	c.r = c.r.prev

	if c.r == nil {
		return io.EOF
	}
	return nil
}

func (c *TextCodec) nextLine() error {
	var err error

	if c.eof {
		return io.EOF
	}

	c.sol = !c.paren
	c.line = ""

	buf := &strings.Builder{}
	blank := true

	for done := false; !done && err == nil; {
		var r rune

		if r, _, err = c.r.ReadRune(); err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			err = c.pop()
			c.eof = errors.Is(err, io.EOF)
			if !blank {
				err = nil
				done = true
			} else {
				buf.Reset()
			}
			continue
		}

		switch r {
		case '\r':
			// ignore

		case '\n':
			if !blank {
				done = true
			} else {
				// ignore lines which are empty or all blank
				buf.Reset()
			}

		default:
			blank = blank && unicode.IsSpace(r)
			buf.WriteRune(r)
		}
	}

	c.line = buf.String()
	return err
}

// startLine makes sure we are reading from the start of the next line, discarding the current one. If the line is
// unconsumed, startLine has no effect. startLine will not return io.EOF if there is still data. That is, if the line
// has no newline, the next call to startLine after consuming it will then return io.EOF
func (c *TextCodec) startLine() error {
	if !c.sol {
		if c.line != "" {
			token, err := c.token(true)
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf(
					"%w: unexpected extra token %s in line",
					ErrUnexpectedToken,
					token,
				)
			}
		}
		if err := c.nextLine(); err != nil {
			return err
		}
	}
	return nil
}

func (c *TextCodec) unread(token string) {
	c.unbuf = token
}

func (c *TextCodec) token(optional bool) (string, error) {
	var token string
	var err error
	type state int

	const (
		text state = iota
		escape
		quote
		qescape
		done
	)

	if c.unbuf != "" {
		token = c.unbuf
		c.unbuf = ""

		return token, nil
	}

	for s := text; s != done && err == nil; {
		for c.line == "" {
			if c.sol || c.paren {
				err = c.nextLine()
				if err != nil {
					if errors.Is(err, io.EOF) && !optional {
						err = io.ErrUnexpectedEOF
					}
					return "", err
				}
			} else {
				if s != text {
					return "", fmt.Errorf("%w: unterminated quote or escape", ErrUnexpectedToken)
				}
				if token == "" {
					if optional {
						return "", io.EOF
					} else {
						return "", io.ErrUnexpectedEOF
					}
				}
				return token, nil
			}
		}

		b := c.line[0]
		c.line = c.line[1:]

		if c.sol {
			c.sol = false
			if unicode.IsSpace(rune(b)) {
				// special case: blank is a token, but only at start of line
				return "", nil
			}
			if b == '$' {
				// $ directives
				var directive string

				for i, r := range c.line {
					if unicode.IsSpace(r) {
						directive = c.line[:i]
						c.line = c.line[i:]
						break
					}
				}

				switch directive {
				case "ORIGIN":
					name, err := c.getName(false)
					if err != nil {
						return "", err
					}
					c.origin = name

				case "INCLUDE":
					filename, err := c.token(false)
					if err != nil {
						return "", err
					}
					name, err := c.getName(true)
					if err != nil {
						if errors.Is(err, io.EOF) {
							name = c.origin
						} else {
							return "", err
						}
					}
					if err = c.push(filename); err != nil {
						return "", err
					}
					c.origin = name

				default:
					return "", fmt.Errorf("%w: unknown $ directive %s", ErrUnexpectedToken, directive)
				}

				if err := c.startLine(); err != nil {
					return "", err
				}
				continue
			}
		}

		switch s {
		case text:
			switch b {
			case ';':
				c.line = ""
				if len(token) > 0 {
					s = done
				}
			case '\\':
				s = escape
			case '"':
				s = quote
			case '(':
				c.paren = true
			case ')':
				c.paren = false
			default:
				if unicode.IsSpace(rune(b)) {
					// eat leading whitespace
					if len(token) > 0 {
						s = done
					}
				} else {
					token += string(b)
				}
			}

		case escape, qescape:
			switch b {
			case '#':
				// special case indicator for unknown rdata
				token += raw
			case '.':
				// special case for domain name parsing
				token += dot
			default:
				if unicode.IsNumber(rune(b)) {
					if len(c.line) < 2 ||
						!unicode.IsNumber(rune(c.line[1])) ||
						!unicode.IsNumber(rune(c.line[2])) {
						return "", fmt.Errorf(
							"%w: illegal number escape \\%c%s",
							ErrUnexpectedToken,
							b, c.line,
						)
					}
					num := 100 * int(b-'0')
					num += 10 * int(c.line[0]-'0')
					num += int(c.line[1] - '0')
					c.line = c.line[2:]
				} else {
					token += string(b)
				}
			}
			if s == qescape {
				s = quote
			} else {
				s = text
			}

		case quote:
			switch b {
			case '"':
				s = text
			case '\\':
				s = qescape
			default:
				token += string(b)
			}

		case done:
		}
	}

	return token, err
}

func (c *TextCodec) getName(optional bool) (Name, error) {
	var n Name

	token, err := c.token(optional)
	if err != nil {
		return n, err
	}
	if token == "" {
		return c.rname, nil
	} else if token == "@" {
		return c.origin, nil
	}

	labels := strings.Split(token, ".")
	for _, l := range labels {
		if l == "" {
			return n, nil // . terminated, so we're done (do not entertain labels beyond; should be error)
		}
		label, err := LabelWithString(l)
		if err != nil {
			return n, err
		}
		n = n.Append(NameWithLabel(label))
	}

	return n.Append(c.origin), nil
}

func (c *TextCodec) getRecord(r *Record) error {
	if err := c.startLine(); err != nil {
		return err
	}

	rname, err := c.getName(false)

	if err != nil {
		return err
	}
	c.rname = rname

	r.RecordHeader.Name = rname
	r.RecordHeader.Class = c.rrclass

	var token string
	var gotTTL, gotClass bool

	for {
		token, err = c.token(false)
		if err != nil {
			return err
		}

		if gotTTL && gotClass {
			break
		}

		if unicode.IsDigit(rune(token[0])) {
			ttl, err := asDuration(token)
			if err != nil {
				return err
			}
			c.ttl = ttl
			gotTTL = true
			continue
		} else if gotClass {
			// not a TTL and we already scanned a class token; existing token expected to be type
			break
		}

		if err := r.RecordHeader.Class.Set(token); err == nil {
			gotClass = true
			continue
		} else {
			// neither TTL nor class token; existing token expected to be a type
			break
		}
	}
	r.RecordHeader.TTL = c.ttl

	if err := r.RecordHeader.Type.Set(token); err != nil {
		return err
	}
	r.RecordData = RecordFromType(r.RecordHeader.Type)

	token, err = c.token(false) // there will be at least one more token for the rdata
	if err != nil {
		return err
	}

	if token == raw {
		token, err = c.token(false)
		if err != nil {
			return err
		}
		length, err := strconv.Atoi(token)
		if err != nil {
			return err
		}
		token, err = c.token(false)
		if err != nil {
			return err
		}
		data, err := hex.DecodeString(token)
		if err != nil {
			return err
		}
		if length != len(data) {
			return fmt.Errorf("%w: specified data length %d, got %d", ErrUnexpectedToken, length, len(data))
		}

		w := NewWireCodec(data)
		return w.Decode(r.RecordData)
	} else {
		c.unread(token)
		return c.Decode(r.RecordData)
	}
}

func (c *TextCodec) getIP4() (net.IP, error) {
	token, err := c.token(false)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(token).To4()
	if ip == nil {
		return nil, fmt.Errorf("%w: cannot parse '%s' as ip4", ErrUnexpectedToken, token)
	}
	return ip, nil
}

func (c *TextCodec) getIP6() (net.IP, error) {
	token, err := c.token(false)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(token).To16()
	if ip == nil {
		return nil, fmt.Errorf("%w: cannot parse '%s' as ip6", ErrUnexpectedToken, token)
	}
	return ip, nil
}

func (c *TextCodec) getNumber() (int, error) {
	token, err := c.token(false)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(token)
}

func asDuration(t string) (time.Duration, error) {
	var d time.Duration

	n, err := strconv.Atoi(t)
	if err != nil {
		d, err = time.ParseDuration(t)
	} else {
		d = time.Duration(n) * time.Second
	}

	return d, err

}

func (c *TextCodec) getBitmap() (Bitmap, error) {
	var b Bitmap
	var r RRType
	for {
		token, err := c.token(true)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			} else {
				return nil, err
			}
		}
		err = r.Set(token)
		if err != nil {
			return nil, err
		}
		b.Set(r)
	}
	return b, nil
}

func (c *TextCodec) Decode(i interface{}) error {
	switch t := i.(type) {
	case *byte:
		n, err := c.getNumber()
		if err != nil {
			return err
		}
		*t = byte(n)

	case *uint16:
		n, err := c.getNumber()
		if err != nil {
			return err
		}
		*t = uint16(n)

	case *uint32:
		n, err := c.getNumber()
		if err != nil {
			return err
		}
		*t = uint32(n)

	case *time.Duration:
		token, err := c.token(false)
		if err != nil {
			return err
		}
		*t, err = asDuration(token)
		if err != nil {
			return err
		}

	case *[4]byte:
		ip, err := c.getIP4()
		if err != nil {
			return err
		}
		copy((*t)[:], ip)

	case *[16]byte:
		ip, err := c.getIP6()
		if err != nil {
			return err
		}
		copy((*t)[:], ip)

	case *[]string:
		var strings []string

		for {
			token, err := c.token(true)
			if err != nil {
				if errors.Is(err, io.EOF) {
					if len(strings) != 0 {
						err = nil
					}
					break
				}
				return err
			}
			strings = append(strings, token)
		}
		*t = strings

	case *[]byte:
		token, err := c.token(false)
		if err != nil {
			return err
		}
		*t, err = base64.StdEncoding.DecodeString(token)
		if err != nil {
			return err
		}

	case *string:
		token, err := c.token(false)
		if err != nil {
			return err
		}
		*t = token

	case *Bitmap:
		b, err := c.getBitmap()
		if err != nil {
			return err
		}
		*t = b

	case *Name:
		name, err := c.getName(false)
		if err != nil {
			return err
		}
		*t = name

	case *Record:
		if err := c.getRecord(t); err != nil {
			return err
		}

	case Decoder:
		if err := t.UnmarshalCodec(c); err != nil {
			return err
		}

	default:
		panic(fmt.Sprintf("unsupported type %T", t))
	}

	return nil
}

func (c *TextCodec) putRecord(r *Record) error {
	if _, err := fmt.Fprintf(
		c.w,
		"%v %v %v %v ",
		r.RecordHeader.Name,
		r.RecordHeader.TTL,
		r.Class(),
		r.Type(),
	); err != nil {
		return err
	}

	if r.RecordData == nil {
		if _, err := fmt.Fprintf(c.w, "; negative cache entry"); err != nil {
			return err
		}
	} else if err := c.Encode(r.RecordData); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "\n"); err != nil {
		return err
	}
	return nil
}

func (c *TextCodec) putUnknown(r *UnknownRecord) error {
	if _, err := fmt.Fprintf(c.w, "\\# %d ", len(r.Data)); err != nil {
		return err
	}

	if _, err := hex.NewEncoder(c.w).Write(r.Data); err != nil {
		return err
	}

	return nil
}

func (c *TextCodec) putQuestion(q *Question) error {
	if _, err := fmt.Fprintf(c.w, "; "); err != nil {
		return err
	}
	if err := c.Encode(q.QName); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "%v %v\n", q.QType, q.QClass); err != nil {
		return err
	}
	return nil
}

func (c *TextCodec) putMessage(m *Message) error {
	if _, err := fmt.Fprintf(c.w, ";; %v: QR=%v, ID=%d\n", m.Opcode, m.QR, m.ID); err != nil {
		return err
	}
	flags := ""
	if m.AA {
		flags += "AA "
	}
	if m.TC {
		flags += "TC "
	}
	if m.RD {
		flags += "RD "
	}
	if m.RA {
		flags += "RA "
	}
	if _, err := fmt.Fprintf(c.w, ";; flags: %s RCode=%v\n", flags, m.RCode); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(c.w, ";; questions:\n"); err != nil {
		return err
	}
	for _, q := range m.Questions {
		if err := c.Encode(q); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, ";; answers:\n"); err != nil {
		return err
	}
	for _, r := range m.Answers {
		if err := c.Encode(r); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, ";; authority:\n"); err != nil {
		return err
	}
	for _, r := range m.Authority {
		if err := c.Encode(r); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(c.w, ";; additional:\n"); err != nil {
		return err
	}
	for _, r := range m.Additional {
		if err := c.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

func (c *TextCodec) putString(s string) error {
	s = strings.ReplaceAll(s, "\"", "\\\"")
	_, err := fmt.Fprintf(c.w, "\"%s\" ", s)
	return err
}

func (c *TextCodec) putBitmap(b Bitmap) error {
	for t := b.Next(InvalidType); t != InvalidType; t = b.Next(t) {
		if _, err := fmt.Fprintf(c.w, "%v ", t); err != nil {
			return err
		}
	}
	return nil
}

func (c *TextCodec) Encode(i interface{}) error {
	switch t := i.(type) {
	case byte, uint16, uint32:
		if _, err := fmt.Fprintf(c.w, "%d ", t); err != nil {
			return err
		}

	case time.Duration:
		if _, err := fmt.Fprintf(c.w, "%v ", t); err != nil {
			return err
		}

	case [4]byte, [16]byte:
		var ip net.IP
		switch t := i.(type) {
		case [4]byte:
			ip = []byte(t[:])
		case [16]byte:
			ip = []byte(t[:])
		}
		if _, err := fmt.Fprintf(c.w, "%v ", ip); err != nil {
			return err
		}

	case []string:
		for _, s := range t {
			if err := c.putString(s); err != nil {
				return err
			}
		}

	case string:
		if err := c.putString(t); err != nil {
			return err
		}

	case []byte:
		if _, err := fmt.Fprintf(c.w, "%s ", base64.StdEncoding.EncodeToString(t)); err != nil {
			return err
		}

	case Name:
		if _, err := fmt.Fprintf(c.w, "%v ", t); err != nil {
			return err
		}

	case Bitmap:
		if err := c.putBitmap(t); err != nil {
			return err
		}

	case *UnknownRecord:
		if err := c.putUnknown(t); err != nil {
			return err
		}

	case *Record:
		if err := c.putRecord(t); err != nil {
			return err
		}

	case *Message:
		if err := c.putMessage(t); err != nil {
			return err
		}

	case *Question:
		if err := c.putQuestion(t); err != nil {
			return err
		}

	case Encoder:
		if err := t.MarshalCodec(c); err != nil {
			return err
		}

	default:
		panic(fmt.Sprintf("unsupported type %T", t))
	}

	return nil
}
