package main

import (
	"context"
	"net/http"
	"strings"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
)

const (
	zoneReload = "/dns/v1/zone/reload/"
	shutdown   = "/dns/v1/shutdown"
)

type RestServer struct {
	http.Server
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

func addHandler(mux *http.ServeMux, path string, h http.Handler) {
	if strings.HasSuffix(path, "/") {
		mux.Handle(path, http.StripPrefix(path, h))
	} else {
		mux.Handle(path, h)
	}
}

func (s *RestServer) Serve(ctx context.Context) {
	h := http.NewServeMux()

	addHandler(h, zoneReload, http.HandlerFunc(s.doZoneReload))
	addHandler(h, shutdown, http.HandlerFunc(s.doShutdown))

	s.Handler = &requestLogger{h}
	s.ErrorLog = logger

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

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *RestServer) doShutdown(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if s.ShutdownServer != nil {
			s.ShutdownServer()
		}

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
