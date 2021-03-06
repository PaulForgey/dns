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
	"unicode/utf8"
)

// Records is a special non-standard entity for identifying a group of resource records in a text file
type Records struct {
	Annotation string
	Records    []*Record
}

// strings or runes of special meaning
var (
	dot = string(0)
	raw = string(1)
)

var ErrUnexpectedToken = errors.New("unexpected token")

var labelReplacer = strings.NewReplacer(`.`, `\.`, `\`, `\\`, `"`, `\"`)

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
		savedOrigin: origin,
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

// Emit commented debug output
func (c *TextCodec) Debug(output string) {
	fmt.Fprintf(c.w, "; %s\n", output)
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

		case ';':
			if blank {
				// present leading whitespace up to a comment as a line starting with one
				buf.Reset()
				blank = false
			}
			buf.WriteRune(r)

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

		b, length := utf8.DecodeRuneInString(c.line)
		if b == utf8.RuneError {
			b = rune(c.line[0])
			length = 1
		}
		c.line = c.line[length:]

		if c.sol {
			c.sol = false
			if unicode.IsSpace(b) {
				// special case: blank is a token, but only at start of line
				return "", nil
			}
			if b == ';' {
				// special case: line starting with comment
				c.line = ""
				c.sol = true
				continue
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
				if unicode.IsSpace(b) {
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
				if unicode.IsNumber(b) {
					if len(c.line) < 2 ||
						!unicode.IsNumber(rune(c.line[0])) ||
						!unicode.IsNumber(rune(c.line[1])) {
						return "", fmt.Errorf(
							"%w: illegal number escape \\%c%s",
							ErrUnexpectedToken,
							b, c.line,
						)
					}
					num := 100 * int(b-'0')
					num += 10 * int(c.line[0]-'0')
					num += int(c.line[1] - '0')
					token += string([]byte{byte(num)})
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

	rrclass := c.rrclass
	ttl := c.ttl
	var rrtype RRType

	var token string
	var gotTTL, gotClass bool
	var exclusive bool

	for {
		token, err = c.token(false)
		if err != nil {
			return err
		}

		if gotTTL && gotClass {
			break
		}

		if unicode.IsDigit(rune(token[0])) {
			ttl, err = asDuration(token)
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

		if err := rrclass.Set(token); err == nil {
			if token[0] == '+' {
				exclusive = true
			}
			c.rrclass = rrclass
			gotClass = true
			continue
		} else {
			// neither TTL nor class token; existing token expected to be a type
			break
		}
	}

	if err := rrtype.Set(token); err != nil {
		return err
	}

	if exclusive {
		r.H = NewMDNSHeader(rname, rrtype, rrclass, ttl, true)
	} else {
		r.H = NewHeader(rname, rrtype, rrclass, ttl)
	}

	token, err = c.token(true) // allow nil rdata
	if err != nil {
		if errors.Is(err, io.EOF) {
			r.D = nil
			err = nil
		}
		return err
	}
	r.D = RecordFromType(r.H.Type())

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
		return w.Decode(r.D)
	} else {
		c.unread(token)
		return c.Decode(r.D)
	}
}

func (c *TextCodec) getRecords(r *Records) error {
	if err := c.startLine(); err != nil {
		return err
	}
	n, err := c.getNumber()
	if err != nil {
		return err
	}
	r.Annotation, err = c.token(true)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	r.Records = make([]*Record, n)
	for i := 0; i < n; i++ {
		nr := &Record{}
		if err := c.getRecord(nr); err != nil {
			return err
		}
		r.Records[i] = nr
	}

	return nil
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

	case *int:
		n, err := c.getNumber()
		if err != nil {
			return err
		}
		*t = int(n)

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

	case *Records:
		if err := c.getRecords(t); err != nil {
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
	if CacheFlush(r.H) {
		// mdns exclusive record (cache flush bit)
		if _, err := fmt.Fprintf(
			c.w,
			"%v %v +%v %v ",
			r.Name(),
			r.H.TTL(),
			r.Class(),
			r.Type(),
		); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(
			c.w,
			"%v %v %v %v ",
			r.Name(),
			r.H.TTL(),
			r.Class(),
			r.Type(),
		); err != nil {
			return err
		}
	}

	if r.D == nil {
		if _, err := fmt.Fprintf(c.w, "; nil"); err != nil {
			return err
		}
	} else if err := c.Encode(r.D); err != nil {
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

func (c *TextCodec) putRecords(r *Records) error {
	if _, err := fmt.Fprintf(c.w, "%d ", len(r.Records)); err != nil {
		return err
	}
	if err := c.putString(r.Annotation); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "\n"); err != nil {
		return err
	}
	for _, rr := range r.Records {
		if err := c.putRecord(rr); err != nil {
			return err
		}
	}

	return nil
}

func (c *TextCodec) putQuestion(q Question) error {
	if _, err := fmt.Fprintf(c.w, "; "); err != nil {
		return err
	}
	if err := c.Encode(q.Name()); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "%v %v\n", q.Type(), q.Class()); err != nil {
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

	if m.EDNS != nil {
		if _, err := fmt.Fprintf(
			c.w,
			";; EDNS: version=%d, msgSize=%d, flags=%04x\n",
			m.EDNS.Version(),
			m.EDNS.MaxMessageSize(),
			m.EDNS.Flags(),
		); err != nil {
			return err
		}
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

func (c *TextCodec) putName(n Name) error {
	if len(n) == 0 {
		_, err := c.w.Write([]byte(". "))
		return err
	}
	for _, l := range n {
		s := labelReplacer.Replace(l.String())
		_, err := fmt.Fprintf(c.w, "%s.", s)
		if err != nil {
			return err
		}
	}
	_, err := c.w.Write([]byte(" "))
	return err
}

func (c *TextCodec) putString(s string) error {
	var size int
	out := &strings.Builder{}

	for b := []byte(s); len(b) > 0; b = b[size:] {
		var r rune

		r, size = utf8.DecodeRune(b)
		if !unicode.IsPrint(r) { // escape unprintable just like invalid utf8
			r = utf8.RuneError
		}

		switch r {
		case '"', '\\':
			out.WriteRune('\\')
			out.WriteRune(r)

		case utf8.RuneError:
			for i := 0; i < size; i++ {
				out.WriteString(fmt.Sprintf("\\%03d", b[i]))
			}

		default:
			out.WriteRune(r)
		}
	}

	_, err := fmt.Fprintf(c.w, "\"%v\" ", out)
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
	case byte, uint16, uint32, int:
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
		if err := c.putName(t); err != nil {
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

	case Question:
		if err := c.putQuestion(t); err != nil {
			return err
		}

	case *Records:
		if err := c.putRecords(t); err != nil {
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
