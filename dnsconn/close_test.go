package dnsconn

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"tessier-ashpool.net/dns"
)

func TestClose(t *testing.T) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	c := NewConn(conn, "udp", "")

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		_, _, err = c.ReadFromIf(context.Background(), func(m *dns.Message) bool {
			return false
		})
		wg.Done()
	}()

	c.Close()

	wg.Wait()
	if err == nil {
		t.Fatal("no error returned")
	}
	t.Logf("expected error after close: %v\n", err)

	// try again with a context instead of close
	c = NewConn(conn, "udp", "")
	ctx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		_, _, err = c.ReadFromIf(ctx, func(m *dns.Message) bool {
			return false
		})
		wg.Done()
	}()
	cancel()
	wg.Wait()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error is %v, not context.Canceled", err)
	}
	t.Logf("expected error after cancel: %v\n", err)

	c.Close()
}
