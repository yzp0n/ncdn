#ifndef XDPCAP_H
#define XDPCAP_H
/*
xdpcap probe, code adopted from https://github.com/cloudflare/xdpcap

Copyright (c) 2019, Cloudflare. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifdef ENABLE_XDPCAP
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 4);  // The max value of XDP_* constants
} xdpcap_hook SEC(".maps");

__attribute__((__always_inline__)) static inline enum xdp_action
xdpcap_exit(struct xdp_md* ctx, void* hook_map, enum xdp_action action) {
  // tail_call
  // Some headers define tail_call (Cilium), others bpf_tail_call (kernel self
  // tests). Use the helper ID directly
  ((int (*)(struct xdp_md*, void*, int))12)(ctx, hook_map, action);
  return action;
}

#define EXIT(action) return xdpcap_exit(ctx, &xdpcap_hook, (action))

#else

#define EXIT(action) return (action)

#endif

#endif // XDPCAP_H
