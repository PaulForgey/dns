package test

import (
	"log"
	"testing"
)

type writer struct {
	testing.TB
}

func (w writer) Write(b []byte) (int, error) {
	w.Logf("%s", string(b))
	return len(b), nil
}

func NewLog(t testing.TB) *log.Logger {
	return log.New(writer{t}, "", log.Lshortfile)
}
