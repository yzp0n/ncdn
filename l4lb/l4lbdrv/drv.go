package l4lbdrv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"go.uber.org/multierr"
)

type Config struct {
	BinPath        string
	InterfaceName  string
	XdpCapHookPath string

	VIP   netip.Addr
	Dests DestinationEntries
}

type L4LB struct {
	cfg *Config

	bindings     *Bindings
	linkAttacher *LinkAttacher
}

func New(cfg *Config) (*L4LB, error) {
	if err := PrepSystemForXDP(); err != nil {
		return nil, fmt.Errorf("Failed to prep system for XDP: %w", err)
	}
	aBinPath, err := filepath.Abs(cfg.BinPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to get absolute path for %s: %w", cfg.BinPath, err)
	}
	var aXdpcapHookPath string
	if cfg.XdpCapHookPath != "" {
		aXdpcapHookPath, err = filepath.Abs(cfg.XdpCapHookPath)
		if err != nil {
			return nil, fmt.Errorf("Failed to get absolute path for %s: %w", cfg.XdpCapHookPath, err)
		}
	}
	bindings, err := BindBalancer(aBinPath, aXdpcapHookPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to bind balancer: %w", err)
	}

	lb := &L4LB{
		cfg:      cfg,
		bindings: bindings,
	}

	var link netlink.Link
	if cfg.InterfaceName == "" {
		slog.Info("No interface name provided, skipping link attachment.")
	} else {
		l, err := netlink.LinkByName(cfg.InterfaceName)
		if err != nil {
			return nil, fmt.Errorf("Failed to find interface %q: %w", cfg.InterfaceName, err)
		}
		link = l
	}
	if link != nil {
		a, err := AttachToLink(link, bindings.LBMain.FD())
		if err != nil {
			return nil, multierr.Combine(err, bindings.Close())
		}
		lb.linkAttacher = a
	}
	if err := lb.Sync(); err != nil {
		return nil, fmt.Errorf("Initial map sync failed: %w", err)
	}

	return lb, nil
}

var hostOrder = binary.LittleEndian

func IPToUint32(ip netip.Addr) (uint32, error) {
	if !ip.Is4() {
		return 0, errors.New("Given IP is not an IPv4 address.")
	}

	ip4 := ip.As4()
	return hostOrder.Uint32(ip4[:]), nil
}

func (lb *L4LB) Sync() error {
	vip4, err := IPToUint32(lb.cfg.VIP)
	if err != nil {
		return fmt.Errorf("vip: %w", err)
	}

	err = lb.bindings.ConfigMap.Update(uint32(0), &LbConfig{
		VipAddress: vip4,
		NumDests:   uint32(len(lb.cfg.Dests) - 1),
	}, 0)
	if err != nil {
		return fmt.Errorf("Failed to update ConfigMap: %w", err)
	}

	keys := make([]uint32, len(lb.cfg.Dests))
	for i := range keys {
		keys[i] = uint32(i)
	}

	_, err = lb.bindings.DestinationArray.BatchUpdate(keys, lb.cfg.Dests, &ebpf.BatchOptions{})
	if err != nil {
		return fmt.Errorf("Failed to update DestinationArray: %w", err)
	}

	return nil
}

func (lb *L4LB) Close() error {
	return lb.bindings.Close()
}

func (lb *L4LB) DumpCounters() error {
	cnt, err := lb.bindings.ReadStatCountersAggregate()
	if err != nil {
		return err
	}

	slog.Info(cnt.String())

	return nil
}

// `PrepSystemForXDP` configures RLIMIT_MEMLOCK to ensure enough room to
// allocate eBPF programs and maps on older Linux systems.
func PrepSystemForXDP() error {
	const RLIMIT_MEMLOCK = 8
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(RLIMIT_MEMLOCK, &rlim); err != nil {
		return fmt.Errorf("Failed to Getrlimit(RLIMIT_MEMLOCK): %v", err)
	}
	slog.Info("Getrlimit(RLIMIT_MEMLOCK)", "Cur", rlim.Cur, "Max", rlim.Max)

	rlim.Cur = math.MaxUint64
	rlim.Max = math.MaxUint64
	if err := syscall.Setrlimit(RLIMIT_MEMLOCK, &rlim); err != nil {
		return fmt.Errorf("Failed to Setrlimit(RLIMIT_MEMLOCK): %v", err)
	}
	slog.Info("Setrlimit(RLIMIT_MEMLOCK)", "Cur", rlim.Cur, "Max", rlim.Max)

	return nil
}
