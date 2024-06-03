#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct process_info {
    char comm[16];
    u16 port;
};

struct bpf_map_def SEC("maps") process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct process_info),
    .max_entries = 1024,
};

SEC("prog")
int bpf_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    u32 *key;
    struct process_info *value;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_DROP;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    key = bpf_map_lookup_elem(&process_map, &ctx->ingress_ifindex);
    if (!key)
        return XDP_PASS;

    value = bpf_map_lookup_elem(&process_map, key);
    if (!value)
        return XDP_PASS;

    if (bpf_ntohs(tcp->source) != value->port || bpf_ntohs(tcp->dest) != value->port)
        return XDP_DROP;

    if (strcmp(value->comm, "myprocess") != 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";