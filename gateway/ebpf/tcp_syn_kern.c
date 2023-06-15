// +build ignore

#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf.h> /* NOTE: THIS IS ACTUALLY linux/bpf.h BUT THE BPF_MAP_TYPE_RINGBUF IS MISSING THERE SO THIS IS LOCAL HEADER IN DIR /bpf! */
#include "tcp_syn_kern.h"

struct bpf_map_def SEC("maps") events  = {
   .type = BPF_MAP_TYPE_RINGBUF,
   .max_entries = 256 * 1024 /* 256 KB */,
};

SEC("xdp_event") int perf_event_test(struct xdp_md *ctx) 
{
   // redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
   __u32 action = XDP_PASS; // default action
   int eth_type;
   int ip_type;
   void *data = (void*)(long)ctx->data;
   void *data_end = (void*)(long)ctx->data_end;
   struct ethhdr *eth = data;
   struct iphdr *ip;
   struct ipv6hdr *ipv6;
   struct tcphdr *tcp;

   struct hdr_cursor nh;
   nh.pos = data;

   eth_type = parse_ethhdr(&nh, data_end, &eth);
   if (eth_type < 0) {
    action = XDP_ABORTED;
    goto out;
   }

   if (eth_type == bpf_htons(ETH_P_IP)) {
    ip_type = parse_iphdr(&nh, data_end, &ip);
   }
   else if (eth_type == bpf_htons(ETH_P_IPV6)) {
    ip_type = parse_ip6hdr(&nh, data_end, &ipv6);
   }
   else {
    // Default action, pass it up the GNU/Linux network stack to be handled
    goto out;
   }

   if (ip_type != IPPROTO_TCP) {
    // We do not need to process non-UDP traffic, pass it up the GNU/Linux network stack to be handled
    goto out;
   }

   if (parse_tcphdr(&nh, data_end, &tcp) < 0) {
    action = XDP_ABORTED;
    goto out;
   }

   /*
   bpf_printk("TCP(source=%u, dest=%u, seq=%d, ", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), tcp->seq);
   bpf_printk("ack_seq=%d, doff=%d, fin=%d, ", tcp->ack_seq, tcp->doff, tcp->fin);
   bpf_printk("rst=%d, psh=%d, urg=%d, ", tcp->rst, tcp->psh, tcp->urg);
   bpf_printk("ece=%d, cwr=%d, syn=%d\n", tcp->ece, tcp->cwr, tcp->syn);
   */
   // Forward TCP Packets from specific port only
   if (bpf_ntohs(tcp->dest) == 7777) {
      unsigned char buf[] = {1, 1, 1, 2, 2};
      int ret = bpf_ringbuf_output(&events, &buf[0], sizeof(buf), 0);

      // In case of perf_event failure abort
      // TODO: Probably this shouldn't impact the program and one should just pass the packet with XDP_PASS 
      // worst case userspace normally deploys the container and does not set the flag that it received a perf_event
      if (ret != 0) {
	 action = XDP_ABORTED;
      }
   }

out:
	return action;
}

//Basic license just for compiling the object code
char __license[] SEC("license") = "GPL";
