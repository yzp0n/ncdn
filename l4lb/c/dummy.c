#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int passthrough_main(struct xdp_md* ctx) {
    return XDP_PASS;
}
