package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/yzp0n/ncdn/types"
)

var nodeId = flag.String("nodeId", "unknown_node", "Name of the node")
var secretToken = flag.String("secretToken", "hirakegoma", "Secret token for authentication")

func probe(targetURL string) (*types.ProbeResult, error) {
	log.Printf("Probing %s...", targetURL)
	defer func() {
		log.Printf("Probing %s...done", targetURL)
	}()

	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DisableKeepAlives = true

	r := &types.ProbeResult{
		ProberNodeId: *nodeId,
		Url:          targetURL,
		Start:        time.Now().UnixNano(),
	}

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create http.Request: %v", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		DNSDone: func(httptrace.DNSDoneInfo) {
			r.DNSEnd = time.Now().UnixNano()
		},
		GotConn: func(httptrace.GotConnInfo) {
			r.ConnectEnd = time.Now().UnixNano()
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			r.RequestEnd = time.Now().UnixNano()
		},
		GotFirstResponseByte: func() {
			r.FirstByte = time.Now().UnixNano()
		},
	}))

	resp, err := t.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to Get %s: %v", targetURL, err)
	}

	// Slurp the response body
	if _, err := io.ReadAll(resp.Body); err != nil {
		return nil, fmt.Errorf("Failed to read response body: %v", err)
	}
	resp.Body.Close()

	r.ResponseCode = resp.StatusCode

	return r, nil
}

func main() {
	flag.Parse()

	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("POST only"))
			return
		}

		// Require secret bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+*secretToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Failed to read request body"))
			return
		}

		var args types.ProbeArgs
		if err := json.Unmarshal(body, &args); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Failed to parse JSON data"))
			return
		}

		res, err := probe(args.TargetUrl)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
			return
		}

		bs, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Failed to marshal JSON response"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(bs)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hi!"))
	})

	log.Println("Listening on :8823...")
	if err := http.ListenAndServe(":8823", nil); err != nil {
		log.Fatal(err)
	}
}
