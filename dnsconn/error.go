package dnsconn

import (
	"errors"
)

var ErrBadNetwork = errors.New("bad network name")
var ErrClosed = errors.New("closed")
var ErrNotConn = errors.New("not connected")
var ErrIsConn = errors.New("connected")
var ErrUnknownInterface = errors.New("unknown interface")
var ErrAddrInUse = errors.New("address in use")
var ErrNoAddr = errors.New("address not found")
var ErrInvalidAddr = errors.New("invalid address")
var ErrInvalidState = errors.New("invalid state")
