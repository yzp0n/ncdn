package gslbcore_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/yzp0n/ncdn/gslb/gslbcore"
	"github.com/yzp0n/ncdn/types"
)

type testLatencyMeasurer struct {
	ProberURL string
}

func (m *testLatencyMeasurer) DebugString() string {
	return fmt.Sprintf("testLatencyMeasurer{%s}", m.ProberURL)
}

func (m *testLatencyMeasurer) MeasureLatency(ctx context.Context, url string) (float64, error) {
	return 0.123, nil
}

func TestGslbCore(t *testing.T) {
	cfg := &gslbcore.Config{
		Pops: []types.PoPInfo{
			{
				Id:                 "shinjuku",
				Ip4:                netip.MustParseAddr("192.0.2.1"),
				LatencyEndpointUrl: "http://192.0.2.1/latencyz",
			},
			{
				Id:                 "shibuya",
				Ip4:                netip.MustParseAddr("192.0.2.2"),
				LatencyEndpointUrl: "http://192.0.2.2/latencyz",
			},
			{
				Id:                 "akiba",
				Ip4:                netip.MustParseAddr("192.0.2.3"),
				LatencyEndpointUrl: "http://192.0.2.3/latencyz",
			},
			{
				Id:                 "atlantis",
				Ip4:                netip.MustParseAddr("192.0.2.254"),
				LatencyEndpointUrl: "http://192.0.2.254/latencyz",
			},
		},
		Regions: []types.RegionInfo{
			{
				Id: "us-west",
				Prefices: []netip.Prefix{
					netip.MustParsePrefix("198.51.100.0/28"),
					netip.MustParsePrefix("198.51.100.192/28"),
				},
				ProberURL: "https://203.0.113.10:8443/probe",
			},
			{
				Id: "us-east",
				Prefices: []netip.Prefix{
					netip.MustParsePrefix("198.51.100.64/28"),
					netip.MustParsePrefix("198.51.100.128/28"),
				},
				ProberURL: "https://203.0.113.20:8443/probe",
			},
			{
				Id: "tokyo",
				Prefices: []netip.Prefix{
					netip.MustParsePrefix("198.51.100.32/28"),
				},
				ProberURL: "https://203.0.113.30:8443/probe",
			},
		},
		FetchPoPStatus: func(ctx context.Context, ip netip.Addr) (*types.PoPStatus, error) {
			if ip.Compare(netip.MustParseAddr("192.0.2.254")) == 0 {
				return nil, errors.New("PoP is down.")
			}

			ps := &types.PoPStatus{
				Id:     "pop-" + ip.String(),
				Uptime: 123.45,
				Load:   float64(ip.AsSlice()[3]),
				Error:  "",
			}

			return ps, nil
		},
		MakeLatencyMeasurer: func(proberURL, secret string) gslbcore.LatencyMeasurer {
			return &testLatencyMeasurer{ProberURL: proberURL}
		},
	}

	c := gslbcore.New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	joinC := make(chan struct{})
	go func() {
		if err := c.Run(ctx); err != nil {
			t.Errorf("GslbCore.Run failed: %v", err)
		}
		close(joinC)
	}()
	cleanup := sync.OnceFunc(func() {
		cancel()
		<-joinC
	})
	defer cleanup()

	// Wait until the first UpdatePoPStatus is done.
	for {
		sn := c.Serial()
		t.Logf("serial: %d", sn)

		if sn >= uint32(len(cfg.Regions)+1) {
			break
		}

		select {
		case <-time.After(100 * time.Millisecond):
			break
		case <-ctx.Done():
			t.Fatalf("Unexpected ctx cancel: %v", ctx.Err())
		}
	}

	testcases := []struct {
		Name     string
		SrcIPStr string
	}{
		{
			Name:     "us-west-0",
			SrcIPStr: "198.51.100.12",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			srcIP := netip.MustParseAddr(tc.SrcIPStr)
			rs := c.Query(srcIP)
			t.Logf("Query(%s): %v", srcIP, rs)
		})
	}

}
