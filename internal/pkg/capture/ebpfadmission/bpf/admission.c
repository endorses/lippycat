// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
// Socket-local admission only. Never changes forwarding or domain control state.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct endpoint { __u32 domain; __u8 address[16]; __u16 port; __u8 family; __u8 pad; };
struct address { __u32 domain; __u8 family; __u8 pad[3]; __u8 address[16]; };
struct prefix { __u32 bits; struct address address; };
struct control { __u64 generation; __u32 mode; __u32 no_filters; };
struct decision { __u64 time_ns; __u64 generation; __u32 domain; __u32 reason; __u32 length; __u32 fingerprint; struct endpoint source; struct endpoint destination; __u32 identity_length; __u8 identity[256]; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, struct endpoint); __type(value, __u8); } endpoints SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, struct address); __type(value, __u8); } addresses SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 4096); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, struct prefix); __type(value, __u8); } prefixes SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64); __type(key, __u32); __type(value, struct control); } controls SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 64*16); __type(key, __u32); __type(value, __u64); } counters SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<20); } decisions SEC(".maps");
const volatile __u32 domain = 0;
const volatile __u32 capture_length = 65535;
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u32); } port_policy SEC(".maps");
const volatile __u32 restrict_sip_ports = 0;
const volatile __u32 restrict_rtp_ports = 0;
const volatile __u32 udp_only = 0;
const volatile __u32 esp_enabled = 0;
const volatile __u32 shadow_sample_every = 1;
// 0 reject, 1 endpoint, 2 signaling, 3 independent, 4 no filters,
// 5 nonUDP, 6 fragment, 7 encapsulation, 8 unknown/truncated, 9 shadow,
// 10 degraded-open, 11 evidence lost, 12 explicit predicate rejected (Go prefix).
static __always_inline void count(__u32 reason) {
    __u32 key = domain * 16 + reason;
    __u64 *value = bpf_map_lookup_elem(&counters, &key);
    if (value) (*value)++;
}
static __always_inline int port_allowed(__u32 port, __u32 flag) {
    __u32 *policy = bpf_map_lookup_elem(&port_policy, &port);
    return policy && (*policy & flag);
}
static __always_inline int restricted(void) { count(13); return 0; }
static __always_inline int independent(struct endpoint *e) {
    struct address a = { .domain = e->domain, .family = e->family };
    __builtin_memcpy(a.address, e->address, 16);
    if (bpf_map_lookup_elem(&addresses, &a)) return 1;
    struct prefix p = { .bits = e->family == 4 ? 96 : 192, .address = a };
    return bpf_map_lookup_elem(&prefixes, &p) != 0;
}
static __always_inline int finish(struct __sk_buff *skb, struct control *ctl, __u32 reason, struct endpoint *src, struct endpoint *dst) {
    count(reason);
    if (ctl->mode == 1) {
        count(9);
        if (shadow_sample_every && bpf_get_prandom_u32() % shadow_sample_every == 0) {
            struct decision *d = bpf_ringbuf_reserve(&decisions, sizeof(*d), 0);
            if (d) {
                __builtin_memset(d, 0, sizeof(*d));
                d->time_ns = bpf_ktime_get_ns(); d->generation = ctl->generation;
                d->domain = domain; d->reason = reason; d->length = skb->len;
                // Bounded header fingerprint, not payload or collision-free identity.
                __u32 words[8] = {};
                bpf_skb_load_bytes(skb, 0, words, sizeof(words));
                __u32 hash = 2166136261U;
                #pragma unroll
                for (int i = 0; i < 8; i++) hash = (hash ^ words[i]) * 16777619U;
                d->fingerprint = hash; d->source = *src; d->destination = *dst;
                // Exact transient correlation is possible only for a complete
                // bounded frame. Partial prefixes never establish identity.
                d->identity_length = 0;
                __u32 identity_length = skb->len;
                if (identity_length && identity_length <= sizeof(d->identity)) {
                    // Bound the helper's scalar argument explicitly. A fresh
                    // skb->len read has no verifier range from an earlier read.
                    __u32 bounded_length = identity_length & 255;
                    long copied;
                    if (bounded_length)
                        copied = bpf_skb_load_bytes(skb, 0, d->identity, bounded_length);
                    else
                        copied = bpf_skb_load_bytes(skb, 0, d->identity, 256);
                    if (!copied) d->identity_length = identity_length;
                }
                bpf_ringbuf_submit(d, 0);
            } else count(11);
        }
        return capture_length;
    }
    if (ctl->mode == 2) { count(10); return capture_length; }
    return reason ? capture_length : 0;
}
SEC("socket") int admit(struct __sk_buff *skb) {
    __u32 scope = domain;
    struct control *ctl = bpf_map_lookup_elem(&controls, &scope);
    if (!ctl) return 0;
    struct endpoint src = { .domain = domain }, dst = { .domain = domain };
    __u8 eth[14];
    __u32 off = 14;
    if (bpf_skb_load_bytes(skb, 0, eth, sizeof(eth))) return udp_only ? restricted() : finish(skb,ctl,8,&src,&dst);
    __u16 proto = ((__u16)eth[12] << 8) | eth[13];
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto == 0x8100 || proto == 0x88a8) {
            __u8 vlan[4];
            if (bpf_skb_load_bytes(skb,off,vlan,4)) return udp_only ? restricted() : finish(skb,ctl,8,&src,&dst);
            proto = ((__u16)vlan[2] << 8) | vlan[3]; off += 4;
        }
    }
    __u8 next;
    if (proto == 0x0800) {
        __u8 ip[20];
        if (bpf_skb_load_bytes(skb,off,ip,20) || (ip[0]>>4)!=4 || (ip[0]&15)<5) return udp_only ? restricted() : finish(skb,ctl,8,&src,&dst);
        src.family=dst.family=4;
        __builtin_memcpy(src.address,ip+12,4); __builtin_memcpy(dst.address,ip+16,4);
        next=ip[9];
        if (udp_only && next!=17) return restricted();
        if ((ip[6]&0x3f) || ip[7]) return finish(skb,ctl,6,&src,&dst);
        off+=(ip[0]&15)*4;
    } else if (proto == 0x86dd) {
        __u8 ip[40];
        if (bpf_skb_load_bytes(skb,off,ip,40) || (ip[0]>>4)!=6) return udp_only ? restricted() : finish(skb,ctl,8,&src,&dst);
        src.family=dst.family=6;
        __builtin_memcpy(src.address,ip+8,16); __builtin_memcpy(dst.address,ip+24,16);
        next=ip[6]; off+=40;
        #pragma unroll
        for (int i=0; i<6; i++) {
            if (next==44) {
                __u8 fragment_next;
                if (bpf_skb_load_bytes(skb,off,&fragment_next,1)) return udp_only ? restricted() : finish(skb,ctl,8,&src,&dst);
                if (udp_only && fragment_next!=17) return restricted();
                return finish(skb,ctl,6,&src,&dst);
            }
            if (next==0 || next==43 || next==60 || next==51) {
                __u8 ext[2];
                if (bpf_skb_load_bytes(skb,off,ext,2)) return udp_only ? restricted() : finish(skb,ctl,8,&src,&dst);
                off += next==51 ? (ext[1]+2)*4 : (ext[1]+1)*8;
                next=ext[0];
            }
        }
        if (next==0 || next==43 || next==60 || next==51 || next==44) return udp_only ? restricted() : finish(skb,ctl,8,&src,&dst);
    } else return udp_only ? restricted() : finish(skb,ctl,8,&src,&dst);
    if (udp_only && next!=17) return restricted();
    if (next==50 && esp_enabled) return finish(skb,ctl,7,&src,&dst);
    if (next!=17) {
        if (next==6 && restrict_sip_ports) {
            __u8 ports[4];
            if (bpf_skb_load_bytes(skb,off,ports,4)) return finish(skb,ctl,8,&src,&dst);
            __u32 a=((__u16)ports[0]<<8)|ports[1], b=((__u16)ports[2]<<8)|ports[3];
            if (!port_allowed(a,1) && !port_allowed(b,1)) return restricted();
        }
        return finish(skb,ctl,5,&src,&dst); // complete allowed TCP input
    }
    __u8 udp[8];
    if (bpf_skb_load_bytes(skb,off,udp,8)) return finish(skb,ctl,8,&src,&dst);
    __u32 udp_length=((__u16)udp[4]<<8)|udp[5];
    if (udp_length<16 || off>skb->len || udp_length>skb->len-off) return finish(skb,ctl,8,&src,&dst);
    src.port=((__u16)udp[0]<<8)|udp[1]; dst.port=((__u16)udp[2]<<8)|udp[3];
    if (src.port==4789 || dst.port==4789 || src.port==8472 || dst.port==8472) return finish(skb,ctl,7,&src,&dst);
    if (restrict_sip_ports && (port_allowed(src.port,1) || port_allowed(dst.port,1))) return finish(skb,ctl,2,&src,&dst);
    // Unconfigured signaling ports: only confidently RTP/RTCP v2 packets are
    // candidates for rejection. Everything else retains userspace SIP discovery.
    __u8 payload[2];
    if (bpf_skb_load_bytes(skb,off+8,payload,2)) return finish(skb,ctl,8,&src,&dst);
    if ((payload[0]&0xc0)!=0x80) {
        if (restrict_sip_ports) return restricted();
        return finish(skb,ctl,2,&src,&dst);
    }
    if (restrict_rtp_ports && !port_allowed(src.port,2) && !port_allowed(dst.port,2)) return restricted();
    if (ctl->no_filters) return finish(skb,ctl,4,&src,&dst);
    if (independent(&src) || independent(&dst)) return finish(skb,ctl,3,&src,&dst);
    if (bpf_map_lookup_elem(&endpoints,&src) || bpf_map_lookup_elem(&endpoints,&dst)) return finish(skb,ctl,1,&src,&dst);
    return finish(skb,ctl,0,&src,&dst);
}
char LICENSE[] SEC("license") = "Dual MIT/GPL";
