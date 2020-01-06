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
	INClass  RRClass = 1
	CSClass  RRClass = 2
	CHClass  RRClass = 3
	HSClass  RRClass = 4
	AnyClass RRClass = 255 // query
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

// Match returns true if either c or n are AnyClass or equal to each other
func (c RRClass) Match(n RRClass) bool {
	return c == AnyClass || n == AnyClass || c == n
}

// Asks returns true if c == n or if c is AnyClass
func (c RRClass) Asks(n RRClass) bool {
	return c == AnyClass || c == n
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
	WKSType     RRType = 11 // pseudo
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

// Match returns true if either t or n are AnyType or equal to each other.
func (t RRType) Match(n RRType) bool {
	return t == AnyType || n == AnyType || t == n
}

// Ask returns true if t == n or t is AnyType. That is, does t ask for n?
func (t RRType) Asks(n RRType) bool {
	return t == AnyType || t == n
}

// A RecordHeader contains the common fields in a Record.
// When creating one to be marshalled, only Name and TTL need to be valid.
// Type is not expected to be valid unless it is either associated with an unknown record type, or if its
// coresponding data is nil (negative cache entries).
type RecordHeader struct {
	Name Name
	TTL  time.Duration

	Type   RRType // decode only, or if RecordData is nil
	Class  RRClass
	Length uint16 // decode only

	CacheFlush bool // mdns

	OriginalTTL   time.Duration // cache only
	Authoritative bool          // cache only

	MaxMessageSize uint16 // decode only, EDNS
	ExtRCode       uint8  // decode only, EDNS
	Version        uint8  // decode only, EDNS
	Flags          uint16 // decode only, EDNS
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
	RecordHeader
	RecordData
}

func (r *Record) String() string {
	w := &strings.Builder{}
	NewTextWriter(w).Encode(r)
	return strings.TrimSpace(w.String())
}

func (r *Record) Type() RRType {
	if r.RecordData == nil {
		return r.RecordHeader.Type
	}
	return r.RecordData.Type()
}

func (r *Record) Class() RRClass {
	return r.RecordHeader.Class
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
	return m.CPU < n.CPU || m.OS < n.OS
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
	return m.RMailbox.Less(n.RMailbox) || m.EMailbox.Less(n.EMailbox)
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
	return m.Preference < n.Preference || m.Name.Less(n.Name)
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
	return m.MName.Less(n.MName) ||
		m.ReName.Less(n.ReName) ||
		m.Serial < n.Serial ||
		m.Refresh < n.Refresh ||
		m.Retry < n.Retry ||
		m.Expire < n.Expire ||
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
	return bytes.Compare(m.Address[:], n.Address[:]) < 0 ||
		m.Protocol < n.Protocol ||
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
	return m.Priority < n.Priority ||
		m.Weight < n.Weight ||
		m.Port < n.Port ||
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
