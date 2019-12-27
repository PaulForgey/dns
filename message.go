package dns

import (
	"fmt"
)

// Rcode is the result code sent by the server is response to a question, and may also be used as an error value.
type Rcode int

const (
	NoError        Rcode = 0
	FormError      Rcode = 1
	ServerFailure  Rcode = 2
	NameError      Rcode = 3
	NotImplemented Rcode = 4
	Refused        Rcode = 5
)

func (r Rcode) Error() string {
	switch r {
	case NoError:
		return "no error"
	case FormError:
		return "form error"
	case ServerFailure:
		return "server failed"
	case NameError:
		return "name error"
	case NotImplemented:
		return "not implemented"
	case Refused:
		return "refused"
	}
	return fmt.Sprintf("unknown rcode 0x%x", int(r))
}

// Opcode is the operation request sent by a client.
type Opcode int

const (
	StandardQuery Opcode = 0
	InverseQuery         = 1
	StatusRequest        = 2
)

func (o Opcode) String() string {
	switch o {
	case StandardQuery:
		return "QUERY"
	case InverseQuery:
		return "IQUERY"
	case StatusRequest:
		return "STATUS"
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
	Rcode      Rcode
	Questions  []*Question
	Answers    []*Record
	Authority  []*Record
	Additional []*Record
}

type Question struct {
	QName  Name
	QType  RRType
	QClass RRClass
	QU     bool // mdns
}

func (q *Question) MarshalCodec(c Codec) error {
	return EncodeSequence(c, q.QName, uint16(q.QType), uint16(q.QClass))
}

func (q *Question) UnmarshalCodec(c Codec) error {
	var qclass RRClass
	err := DecodeSequence(c, &q.QName, (*uint16)(&q.QType), (*uint16)(&qclass))
	if err != nil {
		return err
	}
	if (qclass & 0x8000) != 0 {
		q.QClass = qclass & 0x7fff
		q.QU = true
	} else {
		q.QClass = qclass
		q.QU = false
	}
	return nil
}
