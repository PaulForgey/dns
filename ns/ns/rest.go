package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
)

const (
	zoneReload = "/dns/v1/zone/reload/"
	zoneConf   = "/dns/v1/zone/conf/"
	shutdown   = "/dns/v1/shutdown"
)

type RestServer struct {
	http.Server
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
	addHandler(h, zoneConf, http.HandlerFunc(s.doZoneConf))
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
