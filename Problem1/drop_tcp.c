#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6

// REMOVE these struct definitions:
// struct ethhdr { ... };
// struct iphdr { ... };
// struct tcphdr { ... };

// ...keep your map and function...
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_cnt SEC(".maps");

SEC("xdp")
int drop_tcp_on_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 key = 0;
    __u16 *port;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcp = (struct tcphdr *)((void *)ip + ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    port = bpf_map_lookup_elem(&port_map, &key);
    if (port && tcp->dest == bpf_htons(*port)) {
        __u32 drop_key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&drop_cnt, &drop_key);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        }
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";



