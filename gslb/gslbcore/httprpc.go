package gslbcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"

	"github.com/yzp0n/ncdn/types"
)

func FetchPoPStatusOverHTTP(ctx context.Context, ip netip.Addr) (*types.PoPStatus, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+ip.String()+":8889/statusz", nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	slog.Info("Fetching PoP status from url", slog.String("url", req.URL.String()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response body: %v", err)
	}
	// slog.Info("PoP status response", slog.String("body", string(bs)))

	var ps types.PoPStatus
	if err := json.Unmarshal(bs, &ps); err != nil {
		return nil, err
	}

	return &ps, nil
}

type ProbeOverJSONRPC struct {
	ProberURL string
	Secret    string
}

func (p ProbeOverJSONRPC) DebugString() string {
	return fmt.Sprintf("ProbeOverJSONRPC{ProberURL=%s}", p.ProberURL)
}

func (p ProbeOverJSONRPC) MeasureLatency(ctx context.Context, url string) (float64, error) {
	args := types.ProbeArgs{
		TargetUrl: url,
	}

	argsBs, err := json.Marshal(&args)
	if err != nil {
		return 0, fmt.Errorf("Failed to marshal ProbeArgs: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, p.ProberURL, bytes.NewBuffer(argsBs))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Secret)
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBs, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("Failed to read response body: %v", err)
	}

	slog.Info("Probe response", slog.String("body", string(respBs)))

	var res types.ProbeResult
	if err := json.Unmarshal(respBs, &res); err != nil {
		return 0, fmt.Errorf("Failed to unmarshal ProbeResult: %v", err)
	}

	return float64(res.FirstByte-res.Start) / 1e6, nil
}
