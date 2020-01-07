package main

import (
	"context"
	"net/http"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
)

const (
	zoneReload = "/dns/v1/zone/reload/"
)

type restServer struct {
	zones *ns.Zones
}

func serveREST(ctx context.Context, r *REST, zones *ns.Zones) {
	h := http.NewServeMux()

	srv := &restServer{
		zones: zones,
	}

	h.Handle(zoneReload, http.StripPrefix(zoneReload, http.HandlerFunc(srv.doZoneReload)))

	s := &http.Server{}
	s.Addr = r.Addr
	s.Handler = h

	go func() {
		<-ctx.Done()
		to, cancel := context.WithTimeout(context.Background(), time.Second*10)
		s.Shutdown(to)
		cancel()
	}()
	logger.Printf("REST server starting on %s", r.Addr)
	err := s.ListenAndServe()
	logger.Printf("REST server exiting: %v", err)
}

func (s *restServer) doZoneReload(w http.ResponseWriter, r *http.Request) {
	logger.Printf("zone reload request %s", r.URL.Path)

	switch r.Method {
	case http.MethodPost:
		n, err := dns.NameWithString(r.URL.Path)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		zone := s.zones.Find(n)
		if zone == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		zone.(*ns.Zone).Reload()

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
