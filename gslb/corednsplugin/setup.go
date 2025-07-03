package corednsplugin

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/yzp0n/ncdn/gslb/gslbcore"
	"github.com/yzp0n/ncdn/types"
)

const PluginName = "ncdn_gslb"

var log = clog.NewWithPlugin(PluginName)

func init() {
	plugin.Register(PluginName, setup)
}

func setup(c *caddy.Controller) error {
	origins := plugin.OriginsFromArgsOrServerBlock( /* args=*/ []string{}, c.ServerBlockKeys)
	if len(origins) != 1 {
		return fmt.Errorf("Exactly one server block is required for %s", PluginName)
	}

	var nsA net.IP

	var ccfg gslbcore.Config

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "http_server":
				if !c.NextArg() {
					return c.ArgErr()
				}
				ccfg.HTTPServer = c.Val()

			case "prober_secret":
				if !c.NextArg() {
					return c.ArgErr()
				}
				ccfg.ProberSecret = c.Val()

			case "pop":
				if !c.NextArg() {
					return c.ArgErr()
				}
				pop := types.PoPInfo{Id: c.Val()}
				fmt.Printf("PoP=%s\n", pop.Id)

				// can't rely on `c.NextBlock()` since nesting is not supported.
				if !c.NextArg() || c.Val() != "{" {
					return c.Errf("Expected '{' after pop id")
				}

			POP_LOOP:
				for c.Next() {
					switch c.Val() {
					case "ip4":
						for c.NextArg() {
							s := c.Val()
							ip4, err := netip.ParseAddr(s)
							if err != nil {
								return c.Errf("Failed to parse pop_ip4=%q: %v", s, err)
							}
							pop.Ip4 = ip4
						}

					case "ip4_lookup":
						for c.NextArg() {
							s := c.Val()

							addr, err := net.ResolveIPAddr("ip4", s)
							if err != nil {
								return c.Errf("Failed to resolve pop_ip4_lookup=%q: %v", s, err)
							}
							ip4, ok := netip.AddrFromSlice(addr.IP)
							if !ok {
								return c.Errf("Failed to convert %v to netip.Addr", addr.IP)
							}
							fmt.Printf("Resolved pop_ip4_lookup=%q to %s\n", s, ip4)

							pop.Ip4 = ip4
						}

					case "latency_endpoint_url":
						if !c.NextArg() {
							return c.ArgErr()
						}
						pop.LatencyEndpointUrl = c.Val()

					case "ui_popup_css":
						if !c.NextArg() {
							return c.ArgErr()
						}
						pop.UIPopupCSS = c.Val()

					case "}":
						break POP_LOOP

					default:
						return c.Errf("unknown pop property '%s'", c.Val())
					}
				}
				ccfg.Pops = append(ccfg.Pops, pop)

			case "region":
				if !c.NextArg() {
					return c.ArgErr()
				}
				r := types.RegionInfo{Id: c.Val()}
				fmt.Printf("Region=%s\n", r.Id)

				// can't rely on `c.NextBlock()` since nesting is not supported.
				if !c.NextArg() || c.Val() != "{" {
					return c.Errf("Expected '{' after region id")
				}

			REGION_LOOP:
				for c.Next() {
					switch c.Val() {
					case "prefices":
						for c.NextArg() {
							s := c.Val()
							prefix, err := netip.ParsePrefix(s)
							if err != nil {
								return c.Errf("Failed to parse prefices=%q: %v", s, err)
							}
							r.Prefices = append(r.Prefices, prefix)
						}

					case "prober_url":
						if !c.NextArg() {
							return c.ArgErr()
						}
						r.ProberURL = c.Val()

					case "ui_popup_css":
						if !c.NextArg() {
							return c.ArgErr()
						}
						r.UIPopupCSS = c.Val()

					case "}":
						break REGION_LOOP

					default:
						return c.Errf("unknown region property '%s'", c.Val())
					}
				}
				ccfg.Regions = append(ccfg.Regions, r)

			case "ns_a_addr":
				if !c.NextArg() {
					return c.ArgErr()
				}
				s := c.Val()
				nsA = net.ParseIP(s)
				if nsA == nil {
					return c.Errf("Failed to parse ns_a_addr=%q", s)
				}

			default:
				return c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	if nsA == nil {
		return fmt.Errorf("ns_a_addr is required.")
	}

	core := gslbcore.New(&ccfg)

	dnscfg := dnsserver.GetConfig(c)
	dnscfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		zone := origins[0]
		log.Infof("Added plugin %s. Zone=%s", PluginName, zone)
		p := NewGslb(next, core, zone, nsA)
		go func() {
			if err := p.Run(context.Background()); err != nil {
				clog.Fatalf("Failed to run %s: %v", PluginName, err)
			}
		}()
		return p
	})

	return nil
}
