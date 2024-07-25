package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yzp0n/ncdn/l4lb/l4lbdrv"
)

var lbBin = flag.String("lbBin", "c/lb.o", "Path to XDP lb binary")
var xdpcapHookPath = flag.String("xdpcapHookPath", "/sys/fs/bpf/xdpcap_hook", "Path to XDPCap hook")
var xdpif = flag.String("interface", "net0", "Interface to attach lb prog to")
var vip = flag.String("vip", "192.0.2.10", "VIP address to load balance")
var deststr = flag.String("dests", "", "Comma separated list of destination IP and MAC addresses. (Example: 192.168.88.10;00:00:5e:00:53:01,)")

func parseDest(deststr string) ([]l4lbdrv.DestinationEntry, error) {
	commas := strings.Split(deststr, ",")
	dests := make([]l4lbdrv.DestinationEntry, 0, len(commas))
	for _, c := range commas {
		if c == "" {
			continue
		}

		parts := strings.Split(c, ";")
		if len(parts) != 2 {
			return nil, fmt.Errorf("Invalid destination entry: %s", c)
		}
		ip4 := netip.MustParseAddr(parts[0])
		if ip4.Is6() {
			return nil, fmt.Errorf("Destination must be ipv4 address, but was %s", ip4)
		}

		mac, err := net.ParseMAC(parts[1])
		if err != nil {
			return nil, fmt.Errorf("Invalid MAC address: %s", parts[1])
		}

		dests = append(dests, l4lbdrv.DestinationEntry{
			IPAddr:       ip4,
			HardwareAddr: mac,
		})
	}
	log.Printf("dests: %+v", dests)
	return dests, nil
}

func main() {
	flag.Parse()

	dests, err := parseDest(*deststr)
	if err != nil {
		slog.Error("Failed to parse dest string", slog.String("err", err.Error()))
	}

	cfg := &l4lbdrv.Config{
		BinPath:        *lbBin,
		XdpCapHookPath: *xdpcapHookPath,
		InterfaceName:  *xdpif,
		VIP:            netip.MustParseAddr(*vip),
		Dests:          dests,
	}
	lb, err := l4lbdrv.New(cfg)
	if err != nil {
		log.Panicf("Failed to create l4lb instance: %v", err)
	}
	slog.Info("L4LB started.")
	defer lb.Close()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-ticker.C:
			if err := lb.DumpCounters(); err != nil {
				slog.Error("Failed to dump counters", slog.String("err", err.Error()))
			}
			continue

		case <-done:
			break
		}
		break
	}
	slog.Info("Shutting down.")
}
