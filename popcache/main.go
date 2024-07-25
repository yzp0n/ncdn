package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/yzp0n/ncdn/httprps"
	"github.com/yzp0n/ncdn/types"
)

var originURLStr = flag.String("originURL", "http://localhost:8888", "Origin server URL")
var listenAddr = flag.String("listenAddr", ":8889", "Address to listen on")
var nodeId = flag.String("nodeId", "unknown_node", "Name of the node")

func main() {
	flag.Parse()

	originURL, err := url.Parse(*originURLStr)
	if err != nil {
		log.Fatalf("Failed to parse origin URL %q: %v", *originURLStr, err)
	}

	start := time.Now()

	mux := http.NewServeMux()
	rps := httprps.NewMiddleware(mux)
	http.Handle("/", rps)

	mux.HandleFunc("/statusz", func(w http.ResponseWriter, r *http.Request) {
		s := types.PoPStatus{
			Id:     *nodeId,
			Uptime: time.Since(start).Seconds(),
			Load:   rps.GetRPS(),
		}
		bs, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal PoP status: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(bs)
	})
	mux.HandleFunc("/latencyz", func(w http.ResponseWriter, r *http.Request) {
		// return 204
		w.WriteHeader(http.StatusNoContent)
	})
	mux.Handle("/", &httputil.ReverseProxy{
		// FIXME: actually cache stuff...
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetXForwarded()
			r.Out.Header.Set("X-NCDN-PoPCache-NodeId", *nodeId)
			r.SetURL(originURL)
		},
	})

	log.Printf("Listening on %s...", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatal(err)
	}
}
