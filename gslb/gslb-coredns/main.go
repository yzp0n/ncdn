// gslb-coredns is a custom built CoreDNS binary that includes the
// NCDN `corednsplugin`.
//
// Use this instead of the official CoreDNS binary to be able to use
// `ncdn_gslb` plugin directive in the Corefile.
package main

import (
	_ "github.com/coredns/coredns/plugin/debug"
	_ "github.com/coredns/coredns/plugin/health"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/metrics"
	_ "github.com/coredns/coredns/plugin/pprof"
	_ "github.com/coredns/coredns/plugin/ready"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"

	_ "github.com/yzp0n/ncdn/gslb/corednsplugin"
)

func init() {
	caddy.AppName = "gslb-coredns"
	caddy.AppVersion = "0.0.1"

	// Try to match order of
	// https://github.com/coredns/coredns/blob/master/plugin.cfg
	dnsserver.Directives = []string{
		"debug",
		"log",
		"ready",
		"health",
		"pprof",
		"prometheus",
		"ncdn_gslb",
		"startup",
		"shutdown",
	}
}

func main() {
	coremain.Run()
}
