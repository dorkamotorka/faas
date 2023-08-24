/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/* This file was modified based on multiple examples from https://github.com/xdp-project/xdp-tutorial */

#ifndef __TCP_SYN_KERN_H
#define __TCP_SYN_KERN_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

/* Holds statistics about the XDP action we took */
struct stats_datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
/* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
					     void *data_end,
					     struct ethhdr **ethhdr,
					     struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	/* Expect compiler removes the code that collects VLAN ids */
	return parse_ethhdr_vlan(nh, data_end, ethhdr, 0);
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len = 0;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
        return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr, 
					unsigned char **payload)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < sizeof(*h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end)
		return -1;

	// Parse TCP Options
	if (h->doff > 5) {
		if (h->syn == 1) {
			bpf_printk("[TCPOPTS] Have TCP header options. Header length => %d. Beginning to parse options.\n", len);
			unsigned char *opts = nh->pos + 20; // +20 because this is where the TCP Option part of the TCP packet starts
			if (opts + 1 > data_end) {
			    return -1;
			}

			unsigned int optdata = 0;
			while (optdata <= 40) {
				// Initialize the byte we're parsing and ensure it isn't outside of data_end.
				unsigned char *val = opts + optdata;

				if (val + 1 > data_end) {
					break;
				}
				bpf_printk("[TCPOPTS] Received %d as type code.\n", *val);
				
				// 0x00 indicates end of TCP header options, so break loop.
				if (*val == 0x00) {
					break;
				}
				// 0x01 indicates a NOP which must be skipped.
				else if (*val == 0x01){
					bpf_printk("[TCPOPTS] Skipping NOP.\n");
					optdata++;
					continue;
				}
				// NOTE: The Transmission Control Protocol (TCP) has provision for optional header fields identified by an option kind field.  
				// Options 0 and 1 are exactly one octet which is their kind field.  
				// All other options have their one octet kind field, followed by a one octet length field,
				// followed by length-2 octets of option data.
				// We need to increase by the option's length field for other options.
				else {
					bpf_printk("[TCPOPTS] Found another TCP option! Adjusting by its length.\n");
					// Increase by option length (which is val + 1 since the option length is the second field).
					unsigned char *len = val + 1;
					if (len + 1 > data_end) {
						break;
					}
					bpf_printk("[TCPOPTS] Found option length => %d! Option type => %d.\n", *len, *val);

					// 0xfd indicates a Experiment-1 TCP Option
					if (*val == 0xfd) {
						bpf_printk("[TCPOPTS] Found Experiment-1 TCP Option\n");
						
						// Adjust by +2 = start of TCP Option data.
						unsigned char *payload = val + 2;
						bpf_printk("Payload in the TCP Expriment Option: %s", payload);
						char function[sizeof(len)];
						if (payload + sizeof(payload) <= data_end) {
							__builtin_memcpy(function, payload, sizeof(payload));
							//function[sizeof(payload)] = "\0"; // Null-terminate the string
							bpf_printk("Function name is %s!\n", function);
						}
					}
					// Increment optdata by the option's length.
					//optdata += (*len > 0) ? *len : 1;
					//continue;
				}
				optdata++;		
			}
		}
	}

	nh->pos += len;
	*tcphdr = h;

	return len;
}

#endif /* __TCP_SYN_KERN_H */
