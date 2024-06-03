#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#define PORT 4040

struct bpf_map_def SEC("maps") port_map = {
   .type = BPF_MAP_TYPE_ARRAY,
   .key_size = sizeof(u32),
   .value_size = sizeof(u32),
   .max_entries = 1,
};

SEC("socket")
int drop_tcp_packets(struct __sk_buff *skb) {
    u16 sport, dport;
    u32 port;

    // Get the port number from the map
    bpf_map_lookup_elem(&port_map, &port);
    if (!port)
        port = PORT; // default port if map is empty

    // Parse the packet
    struct iphdr *iph = (struct iphdr *)skb->data;
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

    // Check if it's a TCP packet
    if (iph->protocol!= IPPROTO_TCP)
        return SK_PASS;

    // Get source and destination ports
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);

    // Drop the packet if it's destined for the configured port
    if (dport == port)
        return SK_DROP;

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";