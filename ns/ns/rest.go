package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
)

const (
	zoneReload = "/dns/v1/zone/reload/"
	zoneConf   = "/dns/v1/zone/conf/"
	zoneData   = "/dns/v1/zone/data/"
	shutdown   = "/dns/v1/shutdown"
)

type RestServer struct {
	http.Server
	ctx         context.Context
	allowGET    ns.Access
	allowPUT    ns.Access
	allowDELETE ns.Access
	allowPOST   ns.Access
	allowPATCH  ns.Access

	Conf           *Conf
	Zones          *ns.Zones
	ShutdownServer context.CancelFunc
}

type requestLogger struct {
	h http.Handler
}

func (rl *requestLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Printf("REST: %v %v", r.Method, r.URL)
	rl.h.ServeHTTP(w, r)
}

type requestAuth struct {
	h http.Handler
	s *RestServer
}

func (ra *requestAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := false

	var ip net.IP
	var addr net.Addr

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		ip = net.ParseIP(host)
	}
	if ip == nil {
		logger.Printf("cannot determine source addr of %s: %v", r.RemoteAddr, err)
	} else {
		addr = &net.IPAddr{
			IP: ip,
		}
	}
	// if addr is nil at this point and an ACE needs the ip, the check will deny

	switch r.Method {
	case http.MethodGet:
		auth = ra.s.allowGET.Check(addr, "", r.URL.Path)
	case http.MethodPut:
		auth = ra.s.allowPUT.Check(addr, "", r.URL.Path)
	case http.MethodDelete:
		auth = ra.s.allowDELETE.Check(addr, "", r.URL.Path)
	case http.MethodPost:
		auth = ra.s.allowPOST.Check(addr, "", r.URL.Path)
	case http.MethodPatch:
		auth = ra.s.allowPATCH.Check(addr, "", r.URL.Path)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if auth {
		ra.h.ServeHTTP(w, r)
	} else {
		logger.Printf("denying %s %v from %s", r.Method, r.URL, r.RemoteAddr)
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func addHandler(mux *http.ServeMux, path string, h http.Handler) {
	if strings.HasSuffix(path, "/") {
		mux.Handle(path, http.StripPrefix(path, h))
	} else {
		mux.Handle(path, h)
	}
}

func (s *RestServer) Serve(ctx context.Context) {
	s.allowGET = s.Conf.Access(&s.Conf.REST.AllowGET)
	s.allowPUT = s.Conf.Access(&s.Conf.REST.AllowPUT)
	s.allowDELETE = s.Conf.Access(&s.Conf.REST.AllowDELETE)
	s.allowPOST = s.Conf.Access(&s.Conf.REST.AllowPOST)
	s.allowPATCH = s.Conf.Access(&s.Conf.REST.AllowPATCH)

	h := http.NewServeMux()

	addHandler(h, zoneReload, http.HandlerFunc(s.doZoneReload))
	addHandler(h, zoneConf, http.HandlerFunc(s.doZoneConf))
	addHandler(h, zoneData, http.HandlerFunc(s.doZoneData))
	addHandler(h, shutdown, http.HandlerFunc(s.doShutdown))

	s.Handler = &requestAuth{&requestLogger{h}, s}
	s.ErrorLog = logger
	s.ctx = ctx

	go func() {
		<-ctx.Done()
		to, cancel := context.WithTimeout(context.Background(), time.Second*10)
		s.Shutdown(to)
		cancel()
	}()
	logger.Printf("REST server starting on %s", s.Addr)
	err := s.ListenAndServe()
	logger.Printf("REST server exiting: %v", err)
}

func (s *RestServer) doZoneReload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		n, err := dns.NameWithString(r.URL.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		zone := s.Zones.Zone(n)
		if zone == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		logger.Printf("%v: zone reload request", zone.Name())
		zone.Reload()
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *RestServer) doZoneConf(w http.ResponseWriter, r *http.Request) {
	s.Conf.Lock()
	defer s.Conf.Unlock()

	path := r.URL.Path // must match the configuration json key exactly

	switch r.Method {
	case http.MethodGet:
		var output interface{}
		if path == "" {
			output = s.Conf.Zones
		} else {
			var ok bool
			output, ok = s.Conf.Zones[path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(output)

	case http.MethodDelete:
		c, ok := s.Conf.Zones[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		c.cancel()
		delete(s.Conf.Zones, path)

		w.WriteHeader(http.StatusNoContent)

	case http.MethodPut:
		c := &Zone{}
		err := json.NewDecoder(r.Body).Decode(c)
		if err == nil && c.DbFile != "" {
			err = errors.New("DbFile may not be specified")
		}
		if err == nil {
			err = c.create(s.ctx, s.Conf, path)
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "%v\r\n", err)
			return
		}
		s.Zones.Insert(c.zone, true)
		c.run(s.Zones)

		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *RestServer) doZoneData(w http.ResponseWriter, r *http.Request) {
	var zone *ns.Zone

	path := r.URL.Path // must match the configuration json key exactly
	s.Conf.Lock()
	c, ok := s.Conf.Zones[path]
	if ok {
		zone = c.zone
	}
	s.Conf.Unlock()

	if zone == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	serial, _ := strconv.Atoi(r.FormValue("serial"))

	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/plain")

		_, err := zone.Dump(uint32(serial), dns.AnyClass, func(r *dns.Record) error {
			_, err := fmt.Fprintf(w, "%v\n", r)
			return err
		})
		if err != nil {
			logger.Printf("%v: sending to %v: %v", zone.Name(), r.RemoteAddr, err)
		}

	case http.MethodPut:
		c := dns.NewTextReader(bufio.NewReader(r.Body), zone.Name())
		if err := zone.Xfer(false, func() (*dns.Record, error) {
			r := &dns.Record{}
			if err := c.Decode(r); err != nil {
				return nil, err
			}
			return r, nil
		}); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "%v\r\n", err)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	// XXX MethodPatch with update style fields

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *RestServer) doShutdown(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if s.ShutdownServer != nil {
			s.ShutdownServer()
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
