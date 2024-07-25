package l4lbdrv

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"go.uber.org/multierr"
)

const (
	XDP_ABORTED = uint32(0)
	XDP_DROP    = 1
	XDP_PASS    = 2
	XDP_TX      = 3
)

func XdpRetValToString(retval uint32) string {
	switch retval {
	case XDP_ABORTED:
		return "XDP_ABORTED"
	case XDP_DROP:
		return "XDP_DROP"
	case XDP_PASS:
		return "XDP_PASS"
	case XDP_TX:
		return "XDP_TX"
	default:
		return fmt.Sprintf("Unknown(%d)", retval)
	}
}

type Bindings struct {
	LBMain           *ebpf.Program `ebpf:"lb_main"`
	StatCountersMap  *ebpf.Map     `ebpf:"stat_counters_map"`
	XdpcapHook       *ebpf.Map     `ebpf:"xdpcap_hook"`
	DestinationArray *ebpf.Map     `ebpf:"destinations_map"`
	ConfigMap        *ebpf.Map     `ebpf:"lb_config_map"`
}

func (b *Bindings) Close() error {
	return multierr.Combine(
		b.StatCountersMap.Close(),
		b.XdpcapHook.Close(),
		b.DestinationArray.Close(),
		b.ConfigMap.Close(),
	)
}

func BindBalancer(binPath, xdpcapHookPath string) (*Bindings, error) {
	m, err := ReadDWARFStructs(binPath)
	if err != nil {
		return nil, fmt.Errorf("ReadDWARFStructs(%q): %w", binPath, err)
	}
	if err := LbAssertLayout(m); err != nil {
		return nil, fmt.Errorf("Htdilb2AssertLayout: %w", err)
	}
	slog.Info("Go binding type assertions passed")

	f, err := os.Open(binPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open balancer bin %q: %w", binPath, err)
	}
	defer f.Close()

	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("Failed to read spec %q: %w", binPath, err)
	}

	var bindings Bindings
	if err := spec.LoadAndAssign(&bindings, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 0,
			LogSize:  1 * 1024 * 1024,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			slog.Error("Full verifier", slog.String("error", ve.Error()))
		}
		return nil, fmt.Errorf("Failed to bind spec: %w", err)
	}

	if xdpcapHookPath != "" {
		/*
			if err := os.RemoveAll(xdpcapHookPath); err != nil {
				return nil, fmt.Errorf("Failed to rm previous XdpcapHook at %s: %w", xdpcapHookPath, err)
			}
		*/
		if err := bindings.XdpcapHook.Pin(xdpcapHookPath); err != nil {
			return nil, fmt.Errorf("Failed to pin XdpcapHook: %w", err)
		}
	}

	return &bindings, nil
}

func (b *Bindings) ResetStatCounters() error {
	ncpus := ebpf.MustPossibleCPU()

	zeros := make([][]byte, ncpus)
	for i := range zeros {
		zeros[i] = make([]byte, unsafe.Sizeof(StatCounters{}))
	}

	if err := b.StatCountersMap.Put(int32(0), zeros); err != nil {
		return fmt.Errorf("StatCountersMap.Put: %w", err)
	}
	return nil
}

func (b *Bindings) ReadStatCountersAggregate() (*StatCounters, error) {
	sum := &StatCounters{}

	// b.StatsCountersMap is a per-CPU map. Compute sum over all CPUs.
	var cs [][]byte
	if err := b.StatCountersMap.Lookup(int32(0), &cs); err != nil {
		return nil, fmt.Errorf("StatCountersMap.Lookup: %w", err)
	}
	for _, c := range cs {
		p := (*StatCounters)(unsafe.Pointer(&c[0]))

		sum.Add(p)
	}
	return sum, nil
}

// NowNanoseconds returns a time that can be compared to bpf_ktime_get_ns()
// adopted from https://github.com/iovisor/gobpf/ (Apache 2.0 License)
func NowNanoseconds() uint64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1 /* CLOCK_MONOTONIC */, uintptr(unsafe.Pointer(&ts)), 0)
	sec, nsec := ts.Unix()
	return 1000*1000*1000*uint64(sec) + uint64(nsec)
}

type DestinationEntry struct {
	IPAddr       netip.Addr
	HardwareAddr net.HardwareAddr
}

func (e DestinationEntry) String() string {
	return fmt.Sprintf("{IPAddr: %v, HardwareAddr: %v}", e.IPAddr, e.HardwareAddr)
}

type DestinationEntries []DestinationEntry

const DestinationEntrySize = 10

func (es DestinationEntries) MarshalBinary() ([]byte, error) {
	buf := make([]byte, len(es)*DestinationEntrySize)
	bs := buf

	for _, e := range es {
		if e.IPAddr.Is6() {
			return nil, fmt.Errorf("destination must be ipv4 address, but was %s", e.IPAddr)
		} else {
			ip4 := e.IPAddr.As4()
			copy(bs[0:4], ip4[:])
			bs = bs[4:]
		}
		copy(bs[0:6], e.HardwareAddr)
		bs = bs[6:]
	}

	return buf, nil
}
