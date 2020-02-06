package dns

import (
	"fmt"
)

// RCode is the result code sent by the server is response to a question, and may also be used as an error value.
type RCode int

const (
	NoError        RCode = 0
	FormError      RCode = 1
	ServerFailure  RCode = 2
	NXDomain       RCode = 3
	NotImplemented RCode = 4
	Refused        RCode = 5
	YXDomain       RCode = 6
	YXRRSet        RCode = 7
	NXRRSet        RCode = 8
	NotAuth        RCode = 9
	NotZone        RCode = 10
	BadVersion     RCode = 16
)

func (r RCode) Error() string {
	switch r {
	case NoError:
		return "no error"
	case FormError:
		return "form error"
	case ServerFailure:
		return "server failed"
	case NXDomain:
		return "name does not exist"
	case NotImplemented:
		return "not implemented"
	case Refused:
		return "refused"
	case YXDomain:
		return "name exists"
	case YXRRSet:
		return "rrset exists"
	case NXRRSet:
		return "rrset does not exist"
	case NotAuth:
		return "not authoritative"
	case NotZone:
		return "section outside of zone"
	case BadVersion:
		return "bad EDNS version"
	}
	return fmt.Sprintf("unknown rcode 0x%x", int(r))
}

// Opcode is the operation request sent by a client.
type Opcode int

const (
	StandardQuery Opcode = 0
	InverseQuery  Opcode = 1
	StatusRequest Opcode = 2
	Notify        Opcode = 4
	Update        Opcode = 5
)

func (o Opcode) String() string {
	switch o {
	case StandardQuery:
		return "QUERY"
	case InverseQuery:
		return "IQUERY"
	case StatusRequest:
		return "STATUS"
	case Notify:
		return "NOTIFY"
	case Update:
		return "UPDATE"
	}
	return fmt.Sprintf("%d", o)
}

// Message is a DNS question or answer sent by either client or server.
type Message struct {
	ID         uint16 // message ID
	QR         bool   // query response
	Opcode     Opcode
	AA         bool // authoritative
	TC         bool // truncated
	RD         bool // recursion desired
	RA         bool // resursion available
	RCode      RCode
	Questions  []Question
	Answers    []*Record
	Authority  []*Record
	Additional []*Record
	EDNS       *EDNS
	NoTC       bool // internal: do not try to recover from truncation
	ClientPort bool // internal: udp message source port was not listening port
}

type Question interface {
	fmt.Stringer
	Encoder
	Decoder
	Name() Name
	Type() RRType
	Class() RRClass
}

// Asks returns true if q would ask for r
func Asks(q Question, r *Record) bool {
	return q.Name().Equal(r.Name()) &&
		q.Type().Asks(r.Type()) &&
		q.Class().Asks(r.Class())
}

type QuestionData struct {
	name   Name
	qtype  uint16
	qclass uint16
}

func (d *QuestionData) MarshalCodec(c Codec) error {
	return EncodeSequence(c, d.name, d.qtype, d.qclass)
}

func (d *QuestionData) UnmarshalCodec(c Codec) error {
	return DecodeSequence(c, &d.name, &d.qtype, &d.qclass)
}

type DNSQuestion QuestionData

func NewDNSQuestion(n Name, qtype RRType, qclass RRClass) *DNSQuestion {
	return &DNSQuestion{
		name:   n,
		qtype:  uint16(qtype),
		qclass: uint16(qclass),
	}
}

func DNSQuestionFromData(d *QuestionData) *DNSQuestion {
	return (*DNSQuestion)(d)
}

func (q *DNSQuestion) MarshalCodec(c Codec) error {
	return (*QuestionData)(q).MarshalCodec(c)
}

func (q *DNSQuestion) UnmarshalCodec(c Codec) error {
	return (*QuestionData)(q).UnmarshalCodec(c)
}

func (q *DNSQuestion) String() string {
	return fmt.Sprintf("%v %v %v", q.Name(), q.Type(), q.Class())
}

func (q *DNSQuestion) Name() Name {
	return q.name
}

func (q *DNSQuestion) Type() RRType {
	return RRType(q.qtype)
}

func (q *DNSQuestion) Class() RRClass {
	return RRClass(q.qclass)
}

type MDNSQuestion QuestionData

func NewMDNSQuestion(n Name, qtype RRType, qclass RRClass, QU bool) *DNSQuestion {
	c := uint16(qclass)
	if QU {
		c |= 0x8000
	}

	return &DNSQuestion{
		name:   n,
		qtype:  uint16(qtype),
		qclass: c,
	}
}

func MDNSQuestionFromData(d *QuestionData) *MDNSQuestion {
	return (*MDNSQuestion)(d)
}

func (m *MDNSQuestion) MarshalCodec(c Codec) error {
	return (*QuestionData)(m).MarshalCodec(c)
}

func (m *MDNSQuestion) UnmarshalCodec(c Codec) error {
	return (*QuestionData)(m).UnmarshalCodec(c)
}

func (m *MDNSQuestion) String() string {
	var s string
	if m.QU() {
		s = "%v (QU) %v %v"
	} else {
		s = "%v %v %v"
	}
	return fmt.Sprintf(s, m.Name(), m.Type(), m.Class())
}

func (m *MDNSQuestion) Name() Name {
	return m.name
}

func (m *MDNSQuestion) Type() RRType {
	return RRType(m.qtype)
}

func (m *MDNSQuestion) Class() RRClass {
	return RRClass(m.qclass & 0x7fff)
}

func (m *MDNSQuestion) QU() bool {
	return (m.qclass & 0x8000) != 0
}
