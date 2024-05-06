//go:build ignore

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "parse_helpers.h"

#define TC_ACT_OK 0
#define MAX_ENTRIES	1024
#define FAAS_PORT 8080
#define CLIENT_TEST_PORT 8082

#define DEBUG

struct tcp_session_key {
  __u16 sport; // idenfities a calling app
	__u16 dport; // NOTE: for some weird reason it doesn't work without this parameter
  __u32 saddr; // identifies a host
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct tcp_session_key);
	__type(value, __u32);
} sessions SEC(".maps");

SEC("xdp") int xdp_ingress(struct xdp_md *ctx)
{
	void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;

  struct hdr_cursor nh;
  nh.pos = data;

  struct ethhdr *eth = data;
  int eth_type;
  eth_type = parse_ethhdr(&nh, data_end, &eth);
  if (eth_type < 0) {
    goto out;
  }

  struct iphdr *ip;
	int ip_type = parse_iphdr(&nh, data_end, &ip);
	if (ip_type != IPPROTO_TCP) {
		goto out;
	}
	if ((void*)(ip + 1) > data_end) {
		goto out;
	}

  struct tcphdr *tcp = nh.pos;
  if ((void*)(tcp + 1) > data_end) {
    goto out;
  }

  if (bpf_ntohs(tcp->dest) != FAAS_PORT && bpf_ntohs(tcp->dest) == CLIENT_TEST_PORT) {
    __u32 dest_port = bpf_ntohs(tcp->dest);

		// We need to update the packet checksum when modifying the header.
		__u64 start0 = bpf_ktime_get_ns();
		int diff = bpf_htons(tcp->dest) - FAAS_PORT;
		tcp->dest = bpf_htons(FAAS_PORT); // Change the destination port to FaaS application port
		tcp->check += bpf_htons(diff);
		if (!tcp->check)
			tcp->check += bpf_htons(diff);
		__u64 finish0 = bpf_ktime_get_ns();
		#ifdef DEBUG
			bpf_printk("XDP : Updated TCP port in the ingress packet and the checksum, time elapsed: %d", (finish0 - start0));
			bpf_printk("XDP : Packet flags (syn: %d, ack: %d, fin: %d)", tcp->syn, tcp->ack, tcp->fin);
		#endif

		// NOTE: Only store port and forward it to user space on the first (tcp syn) packet
		if (tcp->syn == 1) { // && !tcp->ack
			struct tcp_session_key session = {
				.sport = tcp->source,
				.dport = tcp->dest,
				.saddr = ip->saddr,
  		};
			#ifdef DEBUG
				bpf_printk("XDP : Update key is [%d , %d, %d]", session.sport, session.dport, session.saddr);
			#endif
			__u64 start = bpf_ktime_get_ns();
			int ret2 = bpf_map_update_elem(&sessions, &session, &dest_port, BPF_ANY);
			if (ret2 != 0) {
				#ifdef DEBUG
					bpf_printk("XDP : Failed to update element in the map");
				#endif
				goto out;
			}
			__u64 finish = bpf_ktime_get_ns();
			#ifdef DEBUG
				bpf_printk("XDP : Map updated with key-value { [%d , %d] : %d}", session.sport, session.saddr, dest_port);
				bpf_printk("XDP : Time elapsed: %d", (finish - start));
			#endif
			__u64 start2 = bpf_ktime_get_ns();
			int ret = bpf_ringbuf_output(&events, &dest_port, sizeof(dest_port), 0);
			__u64 finish2 = bpf_ktime_get_ns();
			// NOTE: Probably this shouldn't impact the program and one should just pass the packet with XDP_PASS
			if (ret != 0) {
				goto out;
			} else {
				#ifdef DEBUG
					bpf_printk("XDP : Succesfully forwarded port number %d through ring buffer, time elapsed: %d", dest_port, (finish2 - start2));
				#endif
			}
		}
  }
    
out:
  return XDP_PASS;
}

SEC("tc") int tc_egress(struct __sk_buff *ctx) {
	void *data_end = (void *)(unsigned long long)ctx->data_end;
	void *data = (void *)(unsigned long long)ctx->data;
	int ip_type;
	int tcp_type;
	struct hdr_cursor nh;
	struct iphdr *ip;
	struct tcphdr *tcp; 

	nh.pos = data;

	/* Parse Ethernet and IP headers */
	struct ethhdr *eth;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IP)) {
		goto out;
	}

	ip_type = parse_iphdr(&nh, data_end, &ip);
	if (ip_type != IPPROTO_TCP) {
		goto out;
	}
	if ((void*)(ip + 1) > data_end) {
		goto out;
	}

	tcp_type = parse_tcphdr(&nh, data_end, &tcp);
	if ((void*)(tcp + 1) > data_end) {
		goto out;
	}

	if (bpf_ntohs(tcp->source) == FAAS_PORT) {
		struct tcp_session_key session = {
			.sport = tcp->dest,
			.dport = tcp->source,
			.saddr = ip->daddr,
  	};
		bpf_printk("TC : Lookup key is [%d , %d, %d]", session.sport, session.dport, session.saddr);
		__u64 start = bpf_ktime_get_ns();
		int *dest_port = bpf_map_lookup_elem(&sessions, &session);
		__u64 finish = bpf_ktime_get_ns();
		if (!dest_port) {
			#ifdef DEBUG
				bpf_printk("TC : Failed to lookup value");
			#endif
			// NOTE: You cannot drop the packet here, because then it wouldn't work for 8080 (which has no lookup value)
			goto out;
		}

		#ifdef DEBUG
			bpf_printk("TC : Retrieved key-value { [%d , %d] : %d} from map", session.sport, session.saddr, *dest_port);
			bpf_printk("TC : Time elapsed: %d", (finish - start));
		#endif

		// We need to update the packet checksum when modifying the header.
		__u64 start1 = bpf_ktime_get_ns();
		// NOTE: don't recalculate checksum for port 8080 that needs no remapping
		if (*dest_port != FAAS_PORT) {
			int diff = *dest_port - FAAS_PORT;
			tcp->source = bpf_htons(*dest_port); // Change the destination port back to initial port
			tcp->check += bpf_htons(-diff);
			if (!tcp->check)
				tcp->check += bpf_htons(-diff);
			__u64 finish1 = bpf_ktime_get_ns();
			#ifdef DEBUG
				bpf_printk("TC  : Updated TCP port in the egress packet and the checksum, time elapsed: %d", (finish1 - start1));
				bpf_printk("TC  : Packet flags (syn: %d, ack: %d, fin: %d)", tcp->syn, tcp->ack, tcp->fin);
			#endif
		}
	}

out:
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";