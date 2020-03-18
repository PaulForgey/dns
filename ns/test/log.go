package test

import (
	"log"
	"testing"
)

type writer testing.T

func (w *writer) Write(b []byte) (int, error) {
	w.Logf("%s", string(b))
	return len(b), nil
}

func NewLog(t *testing.T) *log.Logger {
	return log.New((*writer)(t), "", log.Lshortfile)
}
