// +build !windows

package dnsconn

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"tessier-ashpool.net/dns"
)

func testNetwork(t *testing.T, network string) error {
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return err
	}
	addr := conn.LocalAddr().(*net.UDPAddr)

	if network == "udp6" {
		addr.IP = net.ParseIP("::1")
	} else {
		addr.IP = net.IPv4(127, 0, 0, 1)
	}

	c := NewConn(conn, network, "")

	var iface string

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		_, iface, _, err = c.ReadFromIf(context.Background(), nil)
		wg.Done()
	}()

	if err2 := c.WriteTo(&dns.Message{}, "", addr, UDPMessageSize); err2 != nil {
		return err2
	}
	wg.Wait()
	if err != nil {
		return err
	}

	if iface == "" {
		return errors.New("no interface name")
	}
	_, err = net.InterfaceByName(iface)
	if err != nil {
		return err
	}

	return nil
}

func TestIface(t *testing.T) {
	if err := testNetwork(t, "udp4"); err != nil {
		t.Fatalf("udp4: %v", err)
	}
	if err := testNetwork(t, "udp6"); err != nil {
		t.Fatalf("udp6: %v", err)
	}
}
