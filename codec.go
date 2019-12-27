package dns

import (
	"io"
)

// The Codec type marshals and demarshals the Message, Question, Record, and Name types in addition to the following required
// types:
// byte, uint16, uint32, [4]byte, [16]byte, []byte, []string, string, time.Duration, Encoder (write), Decoder (read).
// If specific types or records need to be handled specially for the given codec, it should also handle those types preventing
// a fallback to Encoder or Decoder.
type Codec interface {
	Encode(interface{}) error
	Decode(interface{}) error
}

// The Encoder type supports marshalling to any codec
type Encoder interface {
	MarshalCodec(Codec) error
}

// The Decoder type supports demarshalling from any codec
type Decoder interface {
	UnmarshalCodec(Codec) error
}

type nullCodec struct{}

func (n *nullCodec) Encode(_ interface{}) error { return nil }
func (n *nullCodec) Decode(_ interface{}) error { return io.EOF }

// The NullCodec discards anything written to it and returns io.EOF if read
var NullCodec = &nullCodec{}

// WriteSequence is a convenience function writing a sequence of values to a Codec
func EncodeSequence(c Codec, items ...interface{}) error {
	for _, i := range items {
		if err := c.Encode(i); err != nil {
			return err
		}
	}
	return nil
}

// ReadSequence is a convenience function reading a sequence of values from a Codec
func DecodeSequence(c Codec, items ...interface{}) error {
	for _, i := range items {
		if err := c.Decode(i); err != nil {
			return err
		}
	}
	return nil
}
