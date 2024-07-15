package types

import "net/netip"

type PoPInfo struct {
	// The PoP identifier for convenience
	Id string

	// The IPv4 address of the PoP
	Ip4 netip.Addr

	// The URL fetched by probers to measure latency
	LatencyEndpointUrl string

	// [webui] CSS of the region popup
	UIPopupCSS string
}

type RegionInfo struct {
	// The region identifier for convenience
	Id string

	// IPv4 Prefices constituting the user region
	Prefices []netip.Prefix

	// The prober that we will use to represent the region
	ProberURL string

	// [webui] CSS of the region popup
	UIPopupCSS string
}

type PoPStatus struct {
	Id     string  `json:"id"`
	Uptime float64 `json:"uptime"`
	Load   float64 `json:"load"`
	Error  string  `json:"error,omitempty"`
}

type ProbeArgs struct {
	TargetUrl string `json:"target_url"`
}

type ProbeResult struct {
	ProberNodeId string `json:"prober_node_id"`
	Url          string `json:"url"`
	Start        int64  `json:"start"`
	DNSEnd       int64  `json:"dns_end"`
	ConnectEnd   int64  `json:"connect_end"`
	RequestEnd   int64  `json:"request_end"`
	FirstByte    int64  `json:"first_byte"`
	ResponseEnd  int64  `json:"response_end"`
	ResponseCode int    `json:"response_code"`
}
