package l4lbdrv

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var pcapWriter *pcapgo.Writer

func DumpDebugPcap(b []byte) {
	if pcapWriter == nil {
		f, err := os.Create("/tmp/debug.pcap")
		if err != nil {
			panic(err)
		}

		pcapWriter = pcapgo.NewWriter(f)
		if err := pcapWriter.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			panic(err)
		}
	}
	if err := pcapWriter.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(b),
		Length:         len(b),
		InterfaceIndex: 0,
	}, b); err != nil {
		panic(err)
	}
}

func TestL4LB(t *testing.T) {
	vip4 := netip.MustParseAddr("192.0.2.10")
	lbIp4 := netip.MustParseAddr("192.168.0.254")
	lbMAC := []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0xfe}

	cfg := &Config{
		BinPath: "../c/lb.o",
		VIP:     vip4,
		Dests: []DestinationEntry{
			{
				IPAddr:       lbIp4,
				HardwareAddr: lbMAC,
			},
			{
				IPAddr:       netip.MustParseAddr("192.168.0.10"),
				HardwareAddr: []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0x10},
			},
		},
	}
	lb, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create L4LB: %v", err)
	}
	defer lb.Close()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x5e, 0x00, 0x53, 0xff},
		DstMAC:       lbMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		SrcIP:    netip.MustParseAddr("10.0.0.123").AsSlice(),
		DstIP:    vip4.AsSlice(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Errorf("SetNetworkLayerForChecksum: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip4, tcp); err != nil {
		t.Fatalf("Failed to serialize packet: %v", err)
	}

	if err := lb.bindings.ResetStatCounters(); err != nil {
		t.Fatalf("Failed to ResetStatCounters: %v", err)
	}
	DumpDebugPcap(buf.Bytes())
	retval, out, err := lb.bindings.LBMain.Test(buf.Bytes())
	if retval != XDP_TX {
		t.Errorf("Expected xdp.XDP_TX but got %s", XdpRetValToString(retval))
	}
	DumpDebugPcap(out)

	if true {
		packet := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
		t.Logf("buildEncapPacket: packet: %s", packet.Dump())
	}
	cnt, err := lb.bindings.ReadStatCountersAggregate()
	if err != nil {
		t.Fatalf("Failed to ReadStatCountersAggregate: %v", err)
	}
	t.Logf("StatCounters: %+v", cnt)
}
