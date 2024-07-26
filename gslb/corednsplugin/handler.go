package corednsplugin

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"

	"github.com/yzp0n/ncdn/gslb/gslbcore"
)

type Gslb struct {
	Next plugin.Handler

	core     *gslbcore.GslbCore
	zone     string
	nsDomain string
	nsA      net.IP
}

func NewGslb(next plugin.Handler, core *gslbcore.GslbCore, zone string, nsA net.IP) *Gslb {
	return &Gslb{
		Next: next,

		core:     core,
		zone:     zone,
		nsDomain: "ns." + zone,
		nsA:      nsA,
	}
}

func (p *Gslb) Run(ctx context.Context) error {
	return p.core.Run(ctx)
}

var _ = plugin.Handler(&Gslb{})

const Ttl = 120

func (p *Gslb) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	qn := state.QName()
	numLabelsNsDomain := dns.CountLabel(p.nsDomain)
	numSameLabels := dns.CompareDomainName(p.nsDomain, qn)
	switch {
	case numSameLabels == numLabelsNsDomain:
		return p.serveNs(ctx, w, r)

	case numSameLabels == numLabelsNsDomain-1:
		break

	default:
		clog.Debugf("%s is not a subdomain of %s", qn, p.zone)
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	subdomain := qn[:len(qn)-len(p.zone)]
	if subdomain == "" {
		return p.serveRoot(ctx, w, r)
	}
	// Strip the last '.'.
	subdomain = subdomain[:len(subdomain)-1]
	subdomain = strings.ToLower(subdomain)

	srcIP := net.ParseIP(state.IP())
	if opt := r.IsEdns0(); opt != nil {
		for _, edns0 := range opt.Option {
			if edns0.Option() == dns.EDNS0SUBNET {
				srcIP = edns0.(*dns.EDNS0_SUBNET).Address
				break
			}
		}
	}

	var records []dns.RR
	var err error
	switch state.QType() {
	// add logic here to act differently based on the query type
	default:
		records, err = p.A(ctx, state.QName(), subdomain, srcIP)
	}
	if err != nil {
		log.Errorf("err: %v", err)
		return dns.RcodeServerFailure, err
	}

	if len(records) == 0 {
		// Generate NXDOMAIN response.

		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = []dns.RR{p.soaRecord()}

		if err := w.WriteMsg(m); err != nil {
			log.Debugf("WriteMsg err=%v", err)
		}
		return dns.RcodeNameError, nil
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = append(m.Answer, records...)

	if err := w.WriteMsg(m); err != nil {
		log.Debugf("WriteMsg err=%v", err)
	}
	return dns.RcodeSuccess, nil
}

// Name implements the Handler interface.
func (p *Gslb) Name() string { return PluginName }

func (p *Gslb) serveNs(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: p.zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: Ttl},
		A:   p.nsA,
	})

	if err := w.WriteMsg(m); err != nil {
		log.Debugf("WriteMsg err=%v", err)
	}
	return dns.RcodeSuccess, nil
}

func (p *Gslb) serveRoot(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch state.QType() {
	case dns.TypeSOA:
		m.Answer = append(m.Answer, p.soaRecord())

	case dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{
			Hdr: dns.RR_Header{Name: p.zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: Ttl},
			Ns:  p.nsDomain,
		})
	}

	if err := w.WriteMsg(m); err != nil {
		log.Debugf("WriteMsg err=%v", err)
	}
	return dns.RcodeSuccess, nil
}

func (p *Gslb) soaRecord() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: p.zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: Ttl},
		Mbox:    "fixme-contact." + p.zone,
		Ns:      p.nsDomain,
		Serial:  p.core.Serial(),
		Refresh: 900,  // FIXME
		Retry:   900,  // FIXME
		Expire:  1800, // FIXME
		Minttl:  Ttl,
	}
}

func (p *Gslb) A(ctx context.Context, qname, subdomain string, srcIP net.IP) ([]dns.RR, error) {
	records := []dns.RR{}

	// FIXME: we only act on "www.[domain]" for now.
	if "www" == subdomain {
		srcIPv4 := srcIP.To4()
		if srcIPv4 == nil {
			return nil, fmt.Errorf("(net.IP).To4(%v) failed.", srcIP)
		}

		srcIP, ok := netip.AddrFromSlice(srcIPv4)
		if !ok {
			return nil, fmt.Errorf("netip.AddrFromSlice(%v) failed.", srcIPv4)
		}
		ips := p.core.Query(srcIP)

		for _, ip := range ips {
			ip4 := ip.As4()
			records = append(records, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: Ttl},
				A:   ip4[:],
			})
		}
	}

	return records, nil
}
