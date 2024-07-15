package gslbcore

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/yzp0n/ncdn/types"
)

// FetchPoPStatus is a function that fetches PoP status from a PoP.
type FetchPoPStatusFunc func(ctx context.Context, ip netip.Addr) (*types.PoPStatus, error)

type MakeLatencyMeasurerFunc func(proberURL, secret string) LatencyMeasurer

type LatencyMeasurer interface {
	DebugString() string

	// MeasureLatency is a function that measures the latency to the `url`.
	MeasureLatency(ctx context.Context, endpointUrl string) (float64, error)
}

type Config struct {
	Pops         []types.PoPInfo
	Regions      []types.RegionInfo
	ProberSecret string
	HTTPServer   string

	FetchPoPStatus      FetchPoPStatusFunc
	MakeLatencyMeasurer MakeLatencyMeasurerFunc
}

type RegionState struct {
	info       types.RegionInfo
	popLatency []float64
}

type GslbCore struct {
	// shouldn't be changed over lifetime of GslbCore.
	cfg *Config

	// LatencyMeasurer is used to measure latency from a region to a PoP.
	// shouldn't be changed over lifetime of GslbCore.
	latencyMeasurers []LatencyMeasurer

	// pluggable for testing purposes.
	fetchPoPStatus FetchPoPStatusFunc

	// Updated by the `GslbCore.Run()` worker. Access to the fields below should be guarded by `mu`.
	mu       sync.Mutex
	popstate []*types.PoPStatus
	regions  []*RegionState
	serial   uint32
}

func New(cfg *Config) *GslbCore {
	fps := cfg.FetchPoPStatus
	if fps == nil {
		fps = FetchPoPStatusOverHTTP
	}

	mlm := cfg.MakeLatencyMeasurer
	if mlm == nil {
		mlm = func(proberURL, secret string) LatencyMeasurer {
			return ProbeOverJSONRPC{
				ProberURL: proberURL,
				Secret:    secret,
			}
		}
	}

	c := &GslbCore{
		cfg: cfg,

		fetchPoPStatus:   fps,
		latencyMeasurers: make([]LatencyMeasurer, len(cfg.Regions)),

		popstate: make([]*types.PoPStatus, len(cfg.Pops)),
		regions:  make([]*RegionState, len(cfg.Regions)),
		serial:   0,
	}
	for i := range c.popstate {
		c.popstate[i] = &types.PoPStatus{
			Error: "not yet available",
		}
	}
	for i, r := range cfg.Regions {
		c.latencyMeasurers[i] = mlm(r.ProberURL, cfg.ProberSecret)

		popLatency := make([]float64, len(c.cfg.Pops))
		for j := range popLatency {
			// initialize to a large value
			popLatency[j] = 10000000
		}

		c.regions[i] = &RegionState{
			info:       r, // copied for convienience
			popLatency: popLatency,
		}
	}

	return c
}

func (c *GslbCore) Run(ctx context.Context) error {
	if c.cfg.HTTPServer != "" {
		if err := c.spawnHTTPServer(ctx); err != nil {
			return err
		}
	}

	for {
		ctxU, cancel := context.WithTimeout(ctx, 10*time.Second)
		c.UpdatePoPStatus(ctxU)
		cancel()

		ctxUL, cancel := context.WithTimeout(ctx, 30*time.Second)
		c.UpdateLatency(ctxUL)
		cancel()

		// sleep for 30 seconds, or stop running if the context is done
		select {
		case <-time.After(30 * time.Second):
			break

		case <-ctx.Done():
			err := ctx.Err()
			if !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		}
	}
}

func (c *GslbCore) UpdatePoPStatus(ctx context.Context) {
	slog.Info("UpdatePoPStatus start")
	start := time.Now()
	defer func() {
		slog.Info("UpdatePoPStatus done", slog.Duration("took", time.Since(start)))
	}()

	newstate := make([]*types.PoPStatus, len(c.cfg.Pops))
	for i, pop := range c.cfg.Pops {
		slog.Info("Fetching PoP status", slog.String("pop.Id", pop.Id))
		ps, err := c.fetchPoPStatus(ctx, pop.Ip4)
		if err != nil {
			slog.Error("PoP status fetch failed with error", slog.String("pop.Id", pop.Id), slog.String("error", err.Error()))
			newstate[i] = &types.PoPStatus{
				Error: err.Error(),
			}
			continue
		}

		newstate[i] = ps
	}

	c.mu.Lock()
	c.popstate = newstate
	c.serial++
	c.mu.Unlock()
}

func (c *GslbCore) UpdateLatency(ctx context.Context) {
	slog.Info("UpdateLatency start")
	start := time.Now()
	defer func() {
		slog.Info("UpdateLatency done", slog.Duration("took", time.Since(start)))
	}()

	for i, lm := range c.latencyMeasurers {
		slog.Info("Measuring latency from prober", slog.String("latencyMeasurer", lm.DebugString()))

		popLatency := make([]float64, len(c.cfg.Pops))
		for j := range popLatency {
			lat, err := lm.MeasureLatency(ctx, c.cfg.Pops[j].LatencyEndpointUrl)
			if err != nil {
				slog.Error("Failed to measure latency",
					slog.String("latencyMeasurer", lm.DebugString()),
					slog.String("error", err.Error()))
				lat = 20000000 // random long latancy
			}
			popLatency[j] = lat
		}

		c.mu.Lock()
		c.regions[i].popLatency = popLatency
		c.serial++
		c.mu.Unlock()
	}
}

func (c *GslbCore) Serial() uint32 {
	c.mu.Lock()
	ret := c.serial
	c.mu.Unlock()
	return ret
}

func (c *GslbCore) PopIdFromIP(ip netip.Addr) string {
	for _, pop := range c.cfg.Pops {
		if pop.Ip4.Compare(ip) == 0 {
			return pop.Id
		}
	}

	return "<not found>"
}

func (c *GslbCore) Query(srcIP netip.Addr) []netip.Addr {
	slog.Info("Query", slog.String("srcIP", srcIP.String()))

	c.mu.Lock()
	defer c.mu.Unlock()

	// FIXME(student): Implement your own query logic
	return []netip.Addr{c.cfg.Pops[0].Ip4}
}
