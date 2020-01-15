package dns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

var ErrUnknownString = errors.New("unknown string for type")

type RRType uint16
type RRClass uint16

const (
	InvalidClass RRClass = 0
	INClass      RRClass = 1
	CSClass      RRClass = 2
	CHClass      RRClass = 3
	HSClass      RRClass = 4
	NoneClass    RRClass = 254
	AnyClass     RRClass = 255 // query
)

func (c RRClass) String() string {
	switch c {
	case INClass:
		return "IN"
	case CSClass:
		return "CS"
	case CHClass:
		return "CH"
	case HSClass:
		return "HS"
	case NoneClass:
		return "NONE"
	case AnyClass:
		return "*"
	}
	return fmt.Sprintf("CLASS%d", c)
}

// Set assigns a class' value from a string
func (c *RRClass) Set(str string) error {
	ustr := strings.ToUpper(str)
	switch ustr {
	case "IN":
		*c = INClass
	case "CS":
		*c = CSClass
	case "CH":
		*c = CHClass
	case "HS":
		*c = HSClass
	case "NONE":
		*c = NoneClass
	case "*", "ANY":
		*c = AnyClass
	default:
		if strings.HasPrefix(ustr, "CLASS") {
			i, err := strconv.Atoi(ustr[5:])
			if err != nil {
				return err
			}
			*c = RRClass(i)
		} else {
			return ErrUnknownString
		}
	}
	return nil
}

// JSON for reading configuration files
func (c *RRClass) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return c.Set(s)
}

func (c RRClass) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// Match returns true if either c or n are AnyClass, NoneClass, or equal to each other
func (c RRClass) Match(n RRClass) bool {
	return c == AnyClass || c == NoneClass || n == AnyClass || n == NoneClass || c == n
}

// Asks returns true if c == n or if c is AnyClass
func (c RRClass) Asks(n RRClass) bool {
	return c == AnyClass || c == NoneClass || c == n
}

const (
	InvalidType RRType = 0
	AType       RRType = 1
	NSType      RRType = 2
	MDType      RRType = 3
	MFType      RRType = 4
	CNAMEType   RRType = 5
	SOAType     RRType = 6
	MBType      RRType = 7
	MGType      RRType = 8
	MRType      RRType = 9
	NULLType    RRType = 10
	WKSType     RRType = 11 // pseudo(ish)
	PTRType     RRType = 12
	HINFOType   RRType = 13
	MINFOType   RRType = 14
	MXType      RRType = 15
	TXTType     RRType = 16
	AAAAType    RRType = 28
	SRVType     RRType = 33
	EDNSType    RRType = 41  // pseudo
	NSECType    RRType = 47  // pseudo
	IXFRType    RRType = 251 // query
	AXFRType    RRType = 252 // query
	MAILBType   RRType = 253 // query
	MAILAType   RRType = 254 // query
	AnyType     RRType = 255 // query
)

func (r RRType) String() string {
	switch r {
	case AType:
		return "A"
	case NSType:
		return "NS"
	case MDType:
		return "MD"
	case MFType:
		return "MF"
	case CNAMEType:
		return "CNAME"
	case SOAType:
		return "SOA"
	case MBType:
		return "MB"
	case MGType:
		return "MG"
	case MRType:
		return "MR"
	case NULLType:
		return "NULL"
	case WKSType:
		return "WKS"
	case PTRType:
		return "PTR"
	case HINFOType:
		return "HINFO"
	case MINFOType:
		return "MINFO"
	case MXType:
		return "MX"
	case TXTType:
		return "TXT"
	case AAAAType:
		return "AAAA"
	case SRVType:
		return "SRV"
	case EDNSType:
		return "EDNS"
	case NSECType:
		return "NSEC"
	case IXFRType:
		return "IXFR"
	case AXFRType:
		return "AXFR"
	case MAILBType:
		return "MAILB"
	case MAILAType:
		return "MAILA"
	case AnyType:
		return "*"
	}

	return fmt.Sprintf("TYPE%d", r)
}

// Set assigns a types' value from a string.
func (r *RRType) Set(str string) error {
	ustr := strings.ToUpper(str)
	switch ustr {
	case "A":
		*r = AType
	case "NS":
		*r = NSType
	case "MD":
		*r = MDType
	case "MF":
		*r = MFType
	case "CNAME":
		*r = CNAMEType
	case "SOA":
		*r = SOAType
	case "MB":
		*r = MBType
	case "MG":
		*r = MGType
	case "MR":
		*r = MRType
	case "NULL":
		*r = NULLType
	case "WKS":
		*r = WKSType
	case "PTR":
		*r = PTRType
	case "HINFO":
		*r = HINFOType
	case "MINFO":
		*r = MINFOType
	case "MX":
		*r = MXType
	case "TXT":
		*r = TXTType
	case "AAAA":
		*r = AAAAType
	case "SRV":
		*r = SRVType
	case "EDNS":
		*r = EDNSType
	case "NSEC":
		*r = NSECType
	case "IXFR":
		*r = IXFRType
	case "AXFR":
		*r = AXFRType
	case "MAILB":
		*r = MAILBType
	case "MAILA":
		*r = MAILAType
	case "*", "ANY":
		*r = AnyType
	default:
		if strings.HasPrefix(ustr, "TYPE") {
			i, err := strconv.Atoi(ustr[4:])
			if err != nil {
				return err
			}
			*r = RRType(i)
		} else {
			return ErrUnknownString
		}
	}
	return nil
}

// JSON for reading configuration files
func (t *RRType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return t.Set(s)
}

func (t RRType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Match returns true if either t or n are AnyType or equal to each other.
func (t RRType) Match(n RRType) bool {
	return t == AnyType || n == AnyType || t == n
}

// Ask returns true if t == n or t is AnyType. That is, does t ask for n?
func (t RRType) Asks(n RRType) bool {
	return t == AnyType || t == n
}

// the RecordHeader interface identifies the type and class of a record
type RecordHeader interface {
	Encoder
	Decoder
	Name() Name
	Type() RRType
	Class() RRClass
	TTL() time.Duration
	Equal(RecordHeader) bool
}

// the HeaderData type contains uninterpreted header data
type HeaderData struct {
	name    Name
	rrtype  uint16
	rrclass uint16
	ttl     uint32
}

func (h *HeaderData) MarshalCodec(c Codec) error {
	return EncodeSequence(c, h.name, h.rrtype, h.rrclass, h.ttl)
}

func (h *HeaderData) UnmarshalCodec(c Codec) error {
	return DecodeSequence(c, &h.name, &h.rrtype, &h.rrclass, &h.ttl)
}

func (h *HeaderData) Type() RRType {
	return RRType(h.rrtype)
}

// the Header type is a standard unicast resource record header
type Header HeaderData

func NewHeader(name Name, rrtype RRType, rrclass RRClass, ttl time.Duration) *Header {
	return &Header{
		name:    name,
		rrtype:  uint16(rrtype),
		rrclass: uint16(rrclass),
		ttl:     uint32(ttl / time.Second),
	}
}

func (h *Header) MarshalCodec(c Codec) error {
	return (*HeaderData)(h).MarshalCodec(c)
}

func (h *Header) UnmarshalCodec(c Codec) error {
	return (*HeaderData)(h).UnmarshalCodec(c)
}

func HeaderFromData(d *HeaderData) *Header {
	return (*Header)(d)
}

func (h *Header) Equal(m RecordHeader) bool {
	return h.Name().Equal(m.Name()) && h.Type() == m.Type() && h.Class() == m.Class()
}

func (h *Header) Name() Name {
	return h.name
}

func (h *Header) Type() RRType {
	return RRType(h.rrtype)
}

func (h *Header) Class() RRClass {
	return RRClass(h.rrclass)
}

func (h *Header) TTL() time.Duration {
	return time.Duration(h.ttl) * time.Second
}

// the MHeader type is an MDNS resource record header
type MDNSHeader struct {
	*Header
}

func NewMDNSHeader(name Name, rrtype RRType, rrclass RRClass, ttl time.Duration, cacheFlush bool) *MDNSHeader {
	m := &MDNSHeader{NewHeader(name, rrtype, rrclass, ttl)}
	if cacheFlush {
		m.rrclass |= 0x8000
	}
	return m
}

func MDNSHeaderFromData(d *HeaderData) *MDNSHeader {
	return &MDNSHeader{HeaderFromData(d)}
}

func (m *MDNSHeader) CacheFlush() bool {
	return (m.rrclass & 0x8000) != 0
}

func (m *MDNSHeader) Class() RRClass {
	return RRClass(m.rrclass & 0x7fff)
}

type EDNSHeader HeaderData

// the EDNSHeader is an EDNS additional record header
func NewEDNSHeader(maxMessageSize uint16, extRCode uint8, version uint8, flags uint16) *EDNSHeader {
	return &EDNSHeader{
		name:    nil,
		rrtype:  uint16(EDNSType),
		rrclass: maxMessageSize,
		ttl:     uint32(extRCode)<<24 | uint32(version)<<16 | uint32(flags),
	}
}

func EDNSHeaderFromData(d *HeaderData) *EDNSHeader {
	return (*EDNSHeader)(HeaderFromData(d))
}

func (e *EDNSHeader) MarshalCodec(c Codec) error {
	return (*HeaderData)(e).MarshalCodec(c)
}

func (e *EDNSHeader) UnmarshalCodec(c Codec) error {
	return (*HeaderData)(e).UnmarshalCodec(c)
}

func (e *EDNSHeader) Equal(m RecordHeader) bool {
	return false
}

func (e *EDNSHeader) Name() Name {
	return nil
}

func (e *EDNSHeader) Type() RRType {
	return EDNSType
}

func (e *EDNSHeader) Class() RRClass {
	return InvalidClass
}

func (e *EDNSHeader) TTL() time.Duration {
	return 0
}

func (e *EDNSHeader) MaxMessageSize() uint16 {
	return e.rrclass
}

func (e *EDNSHeader) ExtRCode() uint8 {
	return uint8(e.ttl >> 24)
}

func (e *EDNSHeader) SetExtRCode(r uint8) {
	e.ttl = uint32(r<<24) | (e.ttl & 0x00ffffff)
}

func (e *EDNSHeader) Version() uint8 {
	return uint8((e.ttl >> 16) & 0xff)
}

func (e *EDNSHeader) Flags() uint16 {
	return uint16(e.ttl & 0xffff)
}

// The RecordData type describes how to marshal and demarshal via the Encoder and Decoder types
type RecordData interface {
	Encoder
	Decoder
	Type() RRType
	// Less and Equal will panic if given different RecordData type
	Less(RecordData) bool  // MDNS rules comparing binary data (with uncompressed names, of course)
	Equal(RecordData) bool // faster than !(m.Less(n) || n.Less(m))
}

// The Record type fully describes a full resource record.
type Record struct {
	H RecordHeader
	D RecordData
}

func (r *Record) String() string {
	w := &strings.Builder{}
	NewTextWriter(w).Encode(r)
	return strings.TrimSpace(w.String())
}

func (r *Record) Name() Name {
	return r.H.Name()
}

func (r *Record) Type() RRType {
	return r.H.Type()
}

func (r *Record) Class() RRClass {
	return r.H.Class()
}

func (r *Record) Equal(n *Record) bool {
	if r == n {
		return true
	}
	if !r.H.Equal(n.H) {
		return false
	}
	if r.D == n.D {
		return true
	}
	if r.D == nil || n.D == nil {
		return false
	}
	return r.D.Equal(n.D)
}

// Match returns true if the records match for the purposes of an update prereq
func (r *Record) Match(n *Record) bool {
	if !r.Name().Equal(n.Name()) {
		return false
	}
	if !r.Type().Match(n.Type()) || !r.Class().Match(n.Class()) {
		return false
	}
	if r.D == nil || n.D == nil {
		// value independent match
		return true
	}
	return r.D.Equal(n.D)
}

// Less for the Record type is a bit silly for practical use, but allows sorting records to make testing easier
func (r *Record) Less(n *Record) bool {
	rn := r.Name()
	nn := n.Name()
	if rn.Less(nn) {
		return true
	}
	if !rn.Equal(nn) {
		return false
	}
	if r.Type() < n.Type() || r.Type() == n.Type() && r.Class() < n.Class() {
		return true
	}
	if r.Class() != n.Class() {
		return false
	}
	if r.D == nil {
		return n.D != nil
	}
	if n.D == nil {
		return false
	}
	return r.D.Less(n.D)
}

// The UnknownRecord type can store rdata of unknown resource records.
// These records should not be blindly retransmitted. If they contain compressed names, their data will be meaningless.
type UnknownRecord struct {
	rrtype RRType
	Data   []byte
}

func NewUnknownRecord(rrtype RRType) *UnknownRecord {
	return &UnknownRecord{
		rrtype: rrtype,
	}
}

func (rr *UnknownRecord) MarshalCodec(c Codec) error {
	return c.Encode(rr.Data)
}

func (rr *UnknownRecord) UnmarshalCodec(c Codec) error {
	return c.Decode(&rr.Data)
}

func (rr *UnknownRecord) Type() RRType { return rr.rrtype }

func (m *UnknownRecord) Equal(nn RecordData) bool {
	return bytes.Compare(m.Data, nn.(*UnknownRecord).Data) == 0
}

func (m *UnknownRecord) Less(nn RecordData) bool {
	return bytes.Compare(m.Data, nn.(*UnknownRecord).Data) < 0
}

type Options map[uint16][]byte

func (o Options) MarshalCodec(c Codec) error {
	for code, data := range o {
		length := uint16(len(data))
		if err := EncodeSequence(c, code, length); err != nil {
			return err
		}
		if length > 0 {
			if err := c.Encode(data); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *Options) UnmarshalCodec(c Codec) error {
	*o = make(map[uint16][]byte)
	for {
		var code, length uint16
		if err := DecodeSequence(c, &code, &length); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil // expected end
			}
		}
		data := make([]byte, int(length))
		if len(data) > 0 {
			if err := c.Decode(&data); err != nil {
				return err
			}
		}
		(*o)[code] = data
	}
	return nil
}

type Bitmap [][]byte

func (b Bitmap) MarshalCodec(c Codec) error {
	for n, block := range b {
		if len(block) == 0 {
			continue
		}
		if err := c.Encode([]byte{byte(n), byte(len(block))}); err != nil {
			return err
		}
		if err := c.Encode(block); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bitmap) UnmarshalCodec(c Codec) error {
	*b = make([][]byte, 256)
	for {
		var n, l byte
		if err := DecodeSequence(c, &n, &l); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				// it's expected as terminator
				break
			}
			return err
		}
		block := make([]byte, l, 32)
		if err := c.Decode(&block); err != nil {
			return err
		}
		(*b)[n] = block
	}
	return nil
}

func location(t RRType) (window, position, bit int) {
	window = int(t >> 8)
	position = int((t & 0xff) >> 3)
	bit = int(t & 7)
	return
}

// Is returns true if the given type is present in b.
func (b Bitmap) Is(t RRType) bool {
	window, position, bit := location(t)

	block := b[window]
	if position >= len(block) {
		return false
	}
	return (block[position] & (0x80 >> bit)) != 0
}

// First is a convenience function returning the first type in b, or InvalidType if none.
func (b Bitmap) First() RRType {
	return b.Next(InvalidType)
}

// Next returns the next type present after t in b, or InvalidType if none.
func (b Bitmap) Next(t RRType) RRType {
	window, position, bit := location(t)

	mask := byte(0xff >> (bit + 1))
	if mask != 0 && window < len(b) {
		block := b[window]
		if position < len(block) {
			e := block[position] & mask

			if e != 0 {
				for i := 0; i < 8; i++ {
					if (e & 0x80) != 0 {
						return RRType(window<<8 + position<<3 + i)
					}
					e <<= 1
				}
				panic("unreachable")
			}
		}
	}
	position++

	for ; window < len(b); window++ {
		block := b[window]
		for ; position < len(block); position++ {
			e := block[position]
			if e != 0 {
				for i := 0; i < 8; i++ {
					if (e & 0x80) != 0 {
						return RRType(window<<8 + position<<3 + i)
					}
					e <<= 1
				}
				panic("unreachable")
			}
		}
		position = 0
	}

	return InvalidType
}

// Set adds a type to b
func (b *Bitmap) Set(t RRType) {
	window, position, bit := location(t)

	if *b == nil {
		*b = make([][]byte, 256)
	}

	block := (*b)[window]
	if block == nil {
		block = make([]byte, 0, 32)
	}
	if position >= len(block) {
		block = block[:position+1]
	}
	block[position] |= 0x80 >> bit
	(*b)[window] = block
}

// An IPRecordType is any record data type providing an IP address
type IPRecordType interface {
	IP() net.IP
}

// An NSRecordType is any type of authority record providing a name server name.
type NSRecordType interface {
	NS() Name
}

// A NameRecordType is any record with a single (or single important) Name. A record of this type in a result set would
// indicate cooresponding IPRecordType records in the cache appear in the additional section.
type NameRecordType interface {
	RName() Name
}

// RecordFromType instantiates a pointer to a zero value concrete instance of a specific resource record for any known
// class and type. Returns *UnknownRecord if the class and type are not known.
func RecordFromType(rrtype RRType) RecordData {
	switch rrtype {
	case AType:
		return &ARecord{}
	case NSType:
		return &NSRecord{}
	case MDType:
		return &MDRecord{}
	case MFType:
		return &MFRecord{}
	case CNAMEType:
		return &CNAMERecord{}
	case SOAType:
		return &SOARecord{}
	case MBType:
		return &MBRecord{}
	case MGType:
		return &MGRecord{}
	case MRType:
		return &MRRecord{}
	case NULLType:
		return &NULLRecord{}
	case WKSType:
		return &WKSRecord{}
	case PTRType:
		return &PTRRecord{}
	case HINFOType:
		return &HINFORecord{}
	case MINFOType:
		return &MINFORecord{}
	case MXType:
		return &MXRecord{}
	case TXTType:
		return &TXTRecord{}
	case AAAAType:
		return &AAAARecord{}
	case SRVType:
		return &SRVRecord{}
	case EDNSType:
		return &EDNSRecord{}
	case NSECType:
		return &NSECRecord{}
	}
	return NewUnknownRecord(rrtype)
}

// ==========
// CNAME
type CNAMERecord struct {
	Name
}

func (rr *CNAMERecord) Type() RRType { return CNAMEType }

func (m *CNAMERecord) Less(nn RecordData) bool {
	return m.Name.Less(nn.(*CNAMERecord).Name)
}

func (m *CNAMERecord) Equal(nn RecordData) bool {
	return m.Name.Equal(nn.(*CNAMERecord).Name)
}

// ==========
// HINFO
type HINFORecord struct {
	CPU string
	OS  string
}

func (rr *HINFORecord) Type() RRType { return HINFOType }

func (rr *HINFORecord) UnmarshalCodec(c Codec) error {
	return DecodeSequence(c, &rr.CPU, &rr.OS)
}

func (rr *HINFORecord) MarshalCodec(c Codec) error {
	return EncodeSequence(c, rr.CPU, rr.OS)
}

func (m *HINFORecord) Equal(nn RecordData) bool {
	n := nn.(*HINFORecord)
	return m.CPU == n.CPU && m.OS == n.OS
}

func (m *HINFORecord) Less(nn RecordData) bool {
	n := nn.(*HINFORecord)
	return m.CPU < n.CPU || m.CPU == n.CPU && n.OS < m.OS
}

// ==========
// MB
type MBRecord struct {
	Name
}

func (rr *MBRecord) Type() RRType { return MBType }

func (m *MBRecord) Less(nn RecordData) bool {
	return m.Name.Less(nn.(*MBRecord).Name)
}

func (m *MBRecord) Equal(nn RecordData) bool {
	return m.Name.Equal(nn.(*MBRecord).Name)
}

// ==========
// MD
type MDRecord struct {
	Name
}

func (rr *MDRecord) Type() RRType { return MDType }

func (m *MDRecord) Less(nn RecordData) bool {
	return m.Name.Less(nn.(*MDRecord).Name)
}

func (m *MDRecord) Equal(nn RecordData) bool {
	return m.Name.Equal(nn.(*MDRecord).Name)
}

// ==========
// MF
type MFRecord struct {
	Name
}

func (rr *MFRecord) Type() RRType { return MFType }

func (m *MFRecord) Less(nn RecordData) bool {
	return m.Name.Less(nn.(*MFRecord).Name)
}

func (m *MFRecord) Equal(nn RecordData) bool {
	return m.Name.Equal(nn.(*MFRecord).Name)
}

// ==========
// MG
type MGRecord struct {
	Name
}

func (rr *MGRecord) Type() RRType { return MGType }

func (m *MGRecord) Less(nn RecordData) bool {
	return m.Name.Less(nn.(*MGRecord).Name)
}

func (m *MGRecord) Equal(nn RecordData) bool {
	return m.Name.Equal(nn.(*MGRecord).Name)
}

// ==========
// MINFO
type MINFORecord struct {
	RMailbox Name
	EMailbox Name
}

func (rr *MINFORecord) Type() RRType { return MINFOType }

func (rr *MINFORecord) UnmarshalCodec(c Codec) error {
	return DecodeSequence(c, &rr.RMailbox, &rr.EMailbox)
}

func (rr *MINFORecord) MarshalCodec(c Codec) error {
	return EncodeSequence(c, rr.RMailbox, rr.EMailbox)
}

func (m *MINFORecord) Equal(nn RecordData) bool {
	n := nn.(*MINFORecord)
	return m.RMailbox.Equal(n.RMailbox) && m.EMailbox.Equal(n.EMailbox)
}

func (m *MINFORecord) Less(nn RecordData) bool {
	n := nn.(*MINFORecord)
	return m.RMailbox.Less(n.RMailbox) || m.RMailbox.Equal(n.RMailbox) &&
		m.EMailbox.Less(n.EMailbox)
}

// ==========
// MR
type MRRecord struct {
	Name
}

func (rr *MRRecord) Type() RRType { return MRType }

func (m *MRRecord) Less(nn RecordData) bool {
	return m.Name.Less(nn.(*MRRecord).Name)
}

func (m *MRRecord) Equal(nn RecordData) bool {
	return m.Name.Equal(nn.(*MRRecord).Name)
}

// ==========
// MX
type MXRecord struct {
	Preference uint16
	Name
}

func (rr *MXRecord) Type() RRType { return MXType }

func (rr *MXRecord) UnmarshalCodec(c Codec) error {
	return DecodeSequence(c, &rr.Preference, &rr.Name)
}

func (rr *MXRecord) MarshalCodec(c Codec) error {
	return EncodeSequence(c, rr.Preference, rr.Name)
}

func (m *MXRecord) Equal(nn RecordData) bool {
	n := nn.(*MXRecord)
	return m.Preference == n.Preference && m.Name.Equal(n.Name)
}

func (m *MXRecord) Less(nn RecordData) bool {
	n := nn.(*MXRecord)
	return m.Preference < n.Preference || m.Preference == n.Preference &&
		m.Name.Less(n.Name)
}

// ==========
// NULL
type NULLRecord struct {
	Data []byte
}

func (rr *NULLRecord) Type() RRType { return NULLType }

func (rr *NULLRecord) UnmarshalCodec(c Codec) error {
	return c.Decode(&rr.Data)
}

func (rr *NULLRecord) MarshalCodec(c Codec) error {
	return c.Encode(rr.Data)
}

func (m *NULLRecord) Equal(nn RecordData) bool {
	n := nn.(*NULLRecord)
	return bytes.Compare(m.Data, n.Data) == 0
}

func (m *NULLRecord) Less(nn RecordData) bool {
	n := nn.(*NULLRecord)
	return bytes.Compare(m.Data, n.Data) < 0
}

// ==========
// NS
type NSRecord struct {
	Name
}

func (rr *NSRecord) NS() Name     { return rr.Name }
func (rr *NSRecord) Type() RRType { return NSType }

func (m *NSRecord) Less(nn RecordData) bool {
	return m.Name.Less(nn.(*NSRecord).Name)
}

func (m *NSRecord) Equal(nn RecordData) bool {
	return m.Name.Equal(nn.(*NSRecord).Name)
}

// ==========
// PTR
type PTRRecord struct {
	Name
}

func (rr *PTRRecord) Type() RRType { return PTRType }

func (m *PTRRecord) Less(nn RecordData) bool {
	return m.Name.Less(nn.(*PTRRecord).Name)
}

func (m *PTRRecord) Equal(nn RecordData) bool {
	return m.Name.Equal(nn.(*PTRRecord).Name)
}

// ==========
// SOA
type SOARecord struct {
	MName   Name
	ReName  Name
	Serial  uint32
	Refresh time.Duration
	Retry   time.Duration
	Expire  time.Duration
	Minimum time.Duration
}

func (rr *SOARecord) NS() Name     { return rr.MName }
func (rr *SOARecord) RName() Name  { return rr.MName }
func (rr *SOARecord) Type() RRType { return SOAType }

func (rr *SOARecord) UnmarshalCodec(c Codec) error {
	return DecodeSequence(
		c,
		&rr.MName,
		&rr.ReName,
		&rr.Serial,
		&rr.Refresh,
		&rr.Retry,
		&rr.Expire,
		&rr.Minimum,
	)
}

func (rr *SOARecord) MarshalCodec(c Codec) error {
	return EncodeSequence(
		c,
		rr.MName,
		rr.ReName,
		rr.Serial,
		rr.Refresh,
		rr.Retry,
		rr.Expire,
		rr.Minimum,
	)
}

func (m *SOARecord) Equal(nn RecordData) bool {
	n := nn.(*SOARecord)
	return m.MName.Equal(n.MName) &&
		m.ReName.Equal(n.ReName) &&
		m.Serial == n.Serial &&
		m.Refresh == n.Refresh &&
		m.Retry == n.Retry &&
		m.Expire == n.Expire &&
		m.Minimum == n.Minimum
}

func (m *SOARecord) Less(nn RecordData) bool {
	n := nn.(*SOARecord)
	return m.MName.Less(n.MName) || m.MName.Equal(n.MName) &&
		m.ReName.Less(n.ReName) || m.ReName.Equal(n.ReName) &&
		m.Serial < n.Serial || m.Serial == n.Serial &&
		m.Refresh < n.Refresh || m.Refresh == n.Refresh &&
		m.Retry < n.Retry || m.Retry == n.Retry &&
		m.Expire < n.Expire || m.Expire == n.Expire &&
		m.Minimum < n.Minimum
}

// ==========
// TXT
type TXTRecord struct {
	Text []string
}

func (rr *TXTRecord) Type() RRType { return TXTType }

func (rr *TXTRecord) UnmarshalCodec(c Codec) error {
	return c.Decode(&rr.Text)
}

func (rr *TXTRecord) MarshalCodec(c Codec) error {
	return c.Encode(rr.Text)
}

func (m *TXTRecord) Equal(nn RecordData) bool {
	n := nn.(*TXTRecord)
	if len(m.Text) != len(n.Text) {
		return false
	}
	for i := range m.Text {
		if m.Text[i] != n.Text[i] {
			return false
		}
	}
	return true
}

func (m *TXTRecord) Less(nn RecordData) bool {
	n := nn.(*TXTRecord)
	c := len(m.Text) - len(n.Text)
	var j int
	if c < 0 {
		j = len(m.Text)
	} else {
		j = len(n.Text)
	}
	for i := 0; i < j; i++ {
		if m.Text[i] < n.Text[i] {
			return true
		}
		if m.Text[i] > n.Text[i] {
			return false
		}
	}
	return c < 0
}

// ==========
// A
type ARecord struct {
	Address [4]byte
}

func (rr *ARecord) Type() RRType { return AType }

func (rr *ARecord) UnmarshalCodec(c Codec) error {
	return c.Decode(&rr.Address)
}

func (rr *ARecord) MarshalCodec(c Codec) error {
	return c.Encode(rr.Address)
}
func (rr *ARecord) IP() net.IP {
	return net.IP(rr.Address[:])
}

func (m *ARecord) Less(nn RecordData) bool {
	n := nn.(*ARecord)
	return bytes.Compare(m.Address[:], n.Address[:]) < 0
}

func (m *ARecord) Equal(nn RecordData) bool {
	n := nn.(*ARecord)
	return bytes.Compare(m.Address[:], n.Address[:]) == 0
}

// ==========
// WKS
type WKSRecord struct {
	Address  [4]byte
	Protocol byte
	Bitmap   []byte
}

func (rr *WKSRecord) Type() RRType { return WKSType }

func (rr *WKSRecord) UnmarshalCodec(c Codec) error {
	return DecodeSequence(c, &rr.Address, &rr.Protocol, &rr.Bitmap)
}

func (rr *WKSRecord) MarshalCodec(c Codec) error {
	return EncodeSequence(c, rr.Address, rr.Protocol, rr.Bitmap)
}

func (m *WKSRecord) Less(nn RecordData) bool {
	n := nn.(*WKSRecord)
	return bytes.Compare(m.Address[:], n.Address[:]) < 0 || bytes.Compare(m.Address[:], n.Address[:]) == 0 &&
		m.Protocol < n.Protocol || m.Protocol == n.Protocol &&
		bytes.Compare(m.Bitmap, n.Bitmap) < 0
}

func (m *WKSRecord) Equal(nn RecordData) bool {
	n := nn.(*WKSRecord)
	return bytes.Compare(m.Address[:], n.Address[:]) == 0 &&
		m.Protocol == n.Protocol &&
		bytes.Compare(m.Bitmap, n.Bitmap) == 0
}

// ==========
// AAAA
type AAAARecord struct {
	Address [16]byte
}

func (rr *AAAARecord) Type() RRType { return AAAAType }

func (rr *AAAARecord) UnmarshalCodec(c Codec) error {
	return c.Decode(&rr.Address)
}

func (rr *AAAARecord) MarshalCodec(c Codec) error {
	return c.Encode(rr.Address)
}

func (rr *AAAARecord) IP() net.IP {
	return net.IP(rr.Address[:])
}

func (m *AAAARecord) Less(nn RecordData) bool {
	n := nn.(*AAAARecord)
	return bytes.Compare(m.Address[:], n.Address[:]) < 0
}

func (m *AAAARecord) Equal(nn RecordData) bool {
	n := nn.(*AAAARecord)
	return bytes.Compare(m.Address[:], n.Address[:]) == 0
}

// ==========
// SRV
type SRVRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Name
}

func (rr *SRVRecord) Type() RRType { return SRVType }

func (rr *SRVRecord) UnmarshalCodec(c Codec) error {
	return DecodeSequence(c, &rr.Priority, &rr.Weight, &rr.Port, &rr.Name)
}

func (rr *SRVRecord) MarshalCodec(c Codec) error {
	return EncodeSequence(c, rr.Priority, rr.Weight, rr.Port, rr.Name)
}

func (m *SRVRecord) Less(nn RecordData) bool {
	n := nn.(*SRVRecord)
	return m.Priority < n.Priority || m.Priority == n.Priority &&
		m.Weight < n.Weight || m.Weight == n.Weight &&
		m.Port < n.Port || m.Port == n.Port &&
		m.Name.Less(n.Name)
}

func (m *SRVRecord) Equal(nn RecordData) bool {
	n := nn.(*SRVRecord)
	return m.Priority == n.Priority &&
		m.Weight == n.Weight &&
		m.Port == n.Port &&
		m.Name.Equal(n.Name)
}

// ==========
// EDNS
type EDNSRecord struct {
	Options
}

func (rr *EDNSRecord) Type() RRType { return EDNSType }

func (rr *EDNSRecord) UnmarshalCodec(c Codec) error {
	return c.Decode(&rr.Options)
}

func (rr *EDNSRecord) MarshalCodec(c Codec) error {
	return c.Encode(rr.Options)
}

// XXX pseudo record
func (m *EDNSRecord) Less(n RecordData) bool {
	return false
}

func (m *EDNSRecord) Equal(n RecordData) bool {
	return false
}

// ==========
// NSEC
type NSECRecord struct {
	Next  Name
	Types Bitmap
}

func (rr *NSECRecord) Type() RRType { return NSECType }

func (rr *NSECRecord) UnmarshalCodec(c Codec) error {
	return DecodeSequence(c, &rr.Next, &rr.Types)
}

func (rr *NSECRecord) MarshalCodec(c Codec) error {
	return EncodeSequence(c, rr.Next, rr.Types)
}

// XXX pseudo record
func (m *NSECRecord) Less(n RecordData) bool {
	return false
}

func (m *NSECRecord) Equal(n RecordData) bool {
	return false
}
