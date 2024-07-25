#include <assert.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <bpf/bpf_helpers.h>

#include <stdint.h>
#include <sys/types.h>

#define PACKED __attribute__((__packed__))
#define ALIGN8 __attribute__((aligned(8)))

#define ENABLE_XDPCAP
#include "xdpcap.h"

// We use clang built-in memcpy, but need a function signature to provoke it.
void* memcpy(void*, const void*, unsigned long);

#define DEBUG_LB_MAIN 1

// clang-format off
struct stat_counters { /* go:Add,String */
  uint64_t rx_packet_total; // HELP Number of packets received against known VIPs.
  uint64_t rx_total_size; // HELP Total size of packets received against known VIPs.

  uint64_t too_short_packet_total; // HELP Number of packets dropped due to being too short.
  uint64_t non_ipv4_packet_total; // HELP Number of packets dropped due to their IP protocol version not v4.
  uint64_t ip_option_packet_total; // HELP Number of packets dropped due to their IP header having options. (currently not supported)
  uint64_t non_supported_proto_packet_total; // HELP Number of packets dropped due to their protocol not being TCP.
  uint64_t no_vip_match_total; // HELP Number of packets dropped due to their dest IP address not matching any known VIP.
  uint64_t failed_adjust_head_total; // HELP Number of xdp_adjust_head failures.
  uint64_t failed_adjust_tail_total; // HELP Number of xdp_adjust_tail failures.
} ALIGN8;
// clang-format on

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, struct stat_counters);
} stat_counters_map SEC(".maps");

// lb_config contains the global configuration of the load balancer, which is
// universal to all flows that it handles.
struct lb_config { /* go: */
  uint32_t vip_address;
  uint32_t num_dests;
} PACKED;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, struct lb_config);
} lb_config_map SEC(".maps");

// destination_entry carries a info that is needed to construct an encap packet
// to the destination.
struct destination_entry {
  uint32_t ip_address;
  uint8_t mac_address[ETH_ALEN];
} PACKED;

#define DESTINATIONS_SIZE 255 /* go: */

// destinations_map is a map that contains the destination_entry for each
// destination that the load balancer can send packets to.
// `destinations_map[0]` is a special entry that contains the info for filling
// the source header fields.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, (DESTINATIONS_SIZE + 1));
  __type(key, uint32_t);
  __type(value, struct destination_entry);
} destinations_map SEC(".maps");

#if DEBUG_LB_MAIN
#define debugk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debugk(fmt, ...) \
  do {                   \
  } while (0)
#endif

SEC("xdp")
int lb_main(struct xdp_md* ctx) {
  void* data = (void*)(uint64_t)ctx->data;
  void* data_end = (void*)(uint64_t)ctx->data_end;

  // Get pointer to the `stat_counters`. The stats are stored per CPU,
  // and the driver code will sum them up upon read.
  const uint32_t map_key_zero = 0;
  struct stat_counters* c =
      bpf_map_lookup_elem(&stat_counters_map, &map_key_zero);
  if (!c) {
    EXIT(XDP_PASS);
  }

  // Get pointer to the `config`. Since the XDP prog can only access BPF maps,
  // we use an BPF map (actually a `BPF_MAP_TYPE_ARRAY`) with a single entry.
  struct lb_config* config = bpf_map_lookup_elem(&lb_config_map, &map_key_zero);
  if (!config) {
    EXIT(XDP_PASS);
  }

  // Lookup ip address and mac address to be used for the source header fields.
  struct destination_entry* src_entry =
      bpf_map_lookup_elem(&destinations_map, &map_key_zero);
  if (!src_entry) {
    EXIT(XDP_PASS);
  }

  // Check if the packet is long enough to contain the headers we need.
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct tcphdr) >
      data_end) {
    ++c->too_short_packet_total;
    EXIT(XDP_PASS);
  }

  struct ethhdr* eth = data;
  struct iphdr* ip = (struct iphdr*)(eth + 1);

  // Check if the packet is IPv4, has no IP options, is destined to the VIP,
  // and is a TCP packet.
  if (ip->version != 0x4) {
    ++c->non_ipv4_packet_total;
    EXIT(XDP_PASS);
  }
  if (ip->ihl != 0x5) {
    ++c->ip_option_packet_total;
    EXIT(XDP_PASS);
  }
  if (ip->daddr != config->vip_address) {
    ++c->no_vip_match_total;
    EXIT(XDP_PASS);
  }
  if (ip->protocol != IPPROTO_TCP) {
    ++c->non_supported_proto_packet_total;
    EXIT(XDP_PASS);
  }

  // Now, we've verified that the packet is a TCP packet destined to the VIP.
  // Record them in the stats as they are eligible for load balancing.
  ++c->rx_packet_total;
  c->rx_total_size += data_end - data;

  struct tcphdr* tcp = (struct tcphdr*)(ip + 1);

  uint32_t key = ip->saddr + tcp->source;
  debugk("incoming packet: ip=%pI4 port=%u", &ip->saddr, ntohs(tcp->source));

  uint32_t dest_idx = (key % config->num_dests) + 1;
  debugk("dest_idx=%d", dest_idx);
  struct destination_entry* dest = bpf_map_lookup_elem(&destinations_map, &dest_idx);
  if (!dest) {
    bpf_printk("ASSERTION FAILURE: no dest entry for %d", dest_idx);
    EXIT(XDP_DROP);
  }
  debugk("dest ip=%pI4", &dest->ip_address);
  debugk("dest mac=%02x:%02x:%02x", dest->mac_address[0], dest->mac_address[1], dest->mac_address[2]);
  debugk("         %02x:%02x:%02x", dest->mac_address[3], dest->mac_address[4], dest->mac_address[5]);

  // make room for the additional IP header (IPIP encapsulation)
  if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr))) {
    ++c->failed_adjust_head_total;
    EXIT(XDP_DROP);
  }

  // make verifier happy - this is guaranteed by the `bpf_xdp_adjust_head`
  // success, but the verifier is not currently smart enough to know that.
  if (ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr) +
          sizeof(struct iphdr) >
      ctx->data_end) {
    bpf_printk("NOT REACHED!!!");
    EXIT(XDP_DROP);
  }

  // Construct new eth header - the encap packet is from the LB to the
  // destination cache node.
  eth = (void*)(uint64_t)ctx->data;
  eth->h_proto = htons(ETH_P_IP);

  memcpy(eth->h_source, src_entry->mac_address, sizeof(src_entry->mac_address));
  memcpy(eth->h_dest, dest->mac_address, sizeof(dest->mac_address));

  // Construct the IPIP header.
  struct iphdr* ip2 = (void*)(eth + 1);

  ip = (void*)(ip2 + 1);
  uint16_t iphdr_tot_len = ntohs(ip->tot_len); // FIXME - should be always fixed.

  ip2->version = 4;
  ip2->ihl = 0x5;
  ip2->tos = 0;
  ip2->tot_len = htons(iphdr_tot_len + sizeof(struct iphdr));
  ip2->id = ~ip->id;
  ip2->frag_off = htons(IP_DF);
  ip2->ttl = 64;
  ip2->protocol = IPPROTO_IPIP;
  ip2->check = 0;
  ip2->saddr = src_entry->ip_address;
  ip2->daddr = dest->ip_address;

  // Calculate the checksum of the IPIP header.
  uint32_t sum = 0;
  for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
    sum += ((uint16_t*)ip2)[i];
  }
  sum = (sum & 0xffff) + (sum >> 16);
  ip2->check = ~sum;

  // Drop padding of the original packet if needed
  ssize_t padding = ETH_ZLEN - (sizeof(struct ethhdr) + iphdr_tot_len);
  if (padding > 0) {
    if (bpf_xdp_adjust_tail(ctx, -padding)) {
      ++c->failed_adjust_tail_total;
      EXIT(XDP_DROP);
    }
  }

  // Redirect the packet to the destination.
  // FIXME: depending on encap_size, it is possible that the encaped needs
  // padding back again too.
  EXIT(XDP_TX);
}

// see DEBUG_LB_MAIN
#undef debugk

char _license[] SEC("license") = "Dual BSD/GPL";
