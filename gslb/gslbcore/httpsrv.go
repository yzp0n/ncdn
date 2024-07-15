package gslbcore

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"time"
)

type AnnotatedLookup struct {
	Ip    netip.Addr `json:"ip"`
	PopId string     `json:"pop_id"`
}

func (c *GslbCore) spawnHTTPServer(ctx context.Context) error {
	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./gslb/gslbcore/static"))
	mux.HandleFunc("/pops.json", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.WriteString("[")
		for i, p := range c.cfg.Pops {
			if i > 0 {
				buf.WriteString(",")
			}
			buf.Write(p.FormatWebUIJson())
		}
		buf.WriteString("]")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf.Bytes())
	})
	mux.HandleFunc("/regions.json", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		buf.WriteString("[")
		for i, r := range c.cfg.Regions {
			if i > 0 {
				buf.WriteString(",")
			}
			buf.Write(r.FormatWebUIJson())
		}
		buf.WriteString("]")

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf.Bytes())
	})
	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		var srcIP netip.Addr

		srcipStr := r.URL.Query().Get("srcip")
		if srcipStr != "" {
			parsed, err := netip.ParseAddr(srcipStr)
			if err != nil {
				http.Error(w, "Failed to parse srcip", http.StatusBadRequest)
				return
			}

			srcIP = parsed
		}

		slog.Info("Query via HTTP start", slog.String("srcip", srcIP.String()))
		results := c.Query(srcIP)
		slog.Info("Query via HTTP end")
		alus := make([]AnnotatedLookup, len(results))
		for i := range results {
			ip := results[i]
			alus[i] = AnnotatedLookup{
				Ip:    ip,
				PopId: c.PopIdFromIP(ip),
			}
		}

		bs, err := json.Marshal(alus)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bs)
	})
	mux.HandleFunc("/latency_to_pop", func(w http.ResponseWriter, r *http.Request) {
		popId := r.URL.Query().Get("pop_id")
		popIdx := -1
		for i, p := range c.cfg.Pops {
			if p.Id == popId {
				popIdx = i
				break
			}
		}
		if popIdx == -1 {
			http.Error(w, "Invalid pop_id", http.StatusBadRequest)
			return
		}

		latencyMap := make(map[string]float64)
		c.mu.Lock()
		for i, r := range c.regions {
			latencyMap[c.cfg.Regions[i].Id] = r.popLatency[popIdx]
		}
		c.mu.Unlock()

		bs, err := json.Marshal(latencyMap)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bs)
	})
	mux.HandleFunc("/latency_to_region", func(w http.ResponseWriter, r *http.Request) {
		regionId := r.URL.Query().Get("region_id")

		var popLatency []float64
		c.mu.Lock()
		for _, r := range c.regions {
			if r.info.Id == regionId {
				popLatency = slices.Clone(r.popLatency)
				break
			}
		}
		c.mu.Unlock()

		latencyMap := make(map[string]float64)
		for i, pop := range c.cfg.Pops {
			latencyMap[pop.Id] = popLatency[i]
		}

		bs, err := json.Marshal(latencyMap)
		if err != nil {
			http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bs)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})

	laddr := c.cfg.HTTPServer
	srv := &http.Server{
		Addr:    laddr,
		Handler: mux,
	}
	errC := make(chan error)
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			errC <- err
		}
		close(errC)
	}()
	go func() {
		<-ctx.Done()
		err := srv.Shutdown(ctx)
		if err != nil {
			slog.Error("HTTP server shutdown failed", slog.String("error", err.Error()))
		}
	}()

	select {
	case err := <-errC:
		return err
	case <-time.After(time.Second):
		slog.Info("HTTP server is running without error for 1 sec.", slog.String("addr", laddr))
		return nil
	}
}
