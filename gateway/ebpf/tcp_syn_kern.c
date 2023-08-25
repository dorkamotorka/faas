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
#include "common.h"

// #define DEBUG

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

   struct tcphdr *h = nh.pos;
   if (h + 1 > data_end) {
    	action = XDP_ABORTED;
    	goto out;
   }

   int len = h->doff * 4;
   /* Sanity check packet field is valid */
   if(len < sizeof(*h)) {
    	action = XDP_ABORTED;
    	goto out;
   }

   /* Variable-length TCP header, need to use byte-based arithmetic */
   if (nh.pos + len > data_end) {
    	action = XDP_ABORTED;
    	goto out;
   }

   // Parse TCP Options
   if (h->doff > 5) {
	// Parse only packet destined for port 8080
   	if (bpf_ntohs(h->dest) == 8080) {
		// Parse only TCP SYN packets
		if (h->syn == 1) {
			#ifdef PRINT
				bpf_printk("[TCPOPTS] Have TCP header options. Header length => %d. Beginning to parse options.\n", len);
			#endif
			unsigned char *opts = nh.pos + 20; // +20 because this is where the TCP Option part of the TCP packet starts
			if (opts + 1 > data_end) {
				action = XDP_ABORTED;
				goto out;
			}

			unsigned int optdata = 0;
			while (optdata <= 40) {
				// Initialize the byte we're parsing and ensure it isn't outside of data_end.
				unsigned char *val = opts + optdata;
				if (val + 1 > data_end) {
					break;
				}
				#ifdef PRINT
					bpf_printk("[TCPOPTS] Received %d as type code.\n", *val);
				#endif

				// 0x00 indicates end of TCP header options, so break loop.
				if (*val == 0x00) {
					break;
				}
				// 0x01 indicates a NOP which must be skipped.
				else if (*val == 0x01){
					#ifdef PRINT
						bpf_printk("[TCPOPTS] Skipping NOP.\n");
					#endif
					optdata++;
					continue;
				}
				// NOTE: The Transmission Control Protocol (TCP) has provision for optional header fields identified by an option kind field.
				// Options 0 and 1 are exactly one octet which is their kind field.
				// All other options have their one octet kind field, followed by a one octet length field,
				// followed by (length - 2) octets of option data.
				// We need to increase by the option's length field for other options.
				else {
					// Increase by option length (which is val + 1 since the option length is the second field).
					unsigned char *len = val + 1;
					if (len + 1 > data_end) {
						break;
					}

					// 0xfd indicates a Experiment-1 TCP Option
					if (*val == 0xfd) {
						#ifdef PRINT
							bpf_printk("[TCPOPTS] Found Experiment-1 TCP Option\n");
						#endif

						// Adjust by +2 = start of TCP Option data.
						const char *payload = val + 2;
						const unsigned int xlen = *len - 2;
						#ifdef PRINT
							bpf_printk("Payload in the TCP Expriment Option: %s (length: %d)", payload, xlen);
						#endif

						// Need to check this otherwise BPF Verifier fails due to potentially exceeding packet bounds
						// NOTE: The TCP SYN custom payload needs to be exactly 8 bytes in lenght, 
						// because the char pointer is of size 8 bytes,
						// and if the TCP SYN custom payload is less, the char pointer is actaully accessing the data out of packet bound 
						// which is prevented by the BPF verifier
						// This is possible, because the overall packet length (data_end - data) changes by changing the TCP packet, 
						// ie. the TCP SYN custom payload
						if (payload + xlen <= data_end) {

							// NOTE: This is a limitation - because BPF Program doesn't support Dynamic Stack Memory allocation, 
							// so one needs to statically pre-compile time determine the amount of memory (actually the length of the function name)
							// which limits it
							unsigned char perf_data[3];
							unsigned int l = 3;
							if (payload + l <= data_end) {
								// NOTE: memcpy operation is necessary because the bpf_ringbuf_output function is not allowed to access
								// packet data directly, so we need to copy it to another variable instatiated on stack and forward that
								__builtin_memcpy(perf_data, payload, l); 
								#ifdef PRINT
									bpf_printk("Perf Data (spurious output for whatever reason): %s\n", perf_data);
								#endif
								int ret = bpf_ringbuf_output(&events, &perf_data, l, 0);
								
								// NOTE: Probably this shouldn't impact the program and one should just pass the packet with XDP_PASS
								// worst case userspace normally deploys the container and does not set the flag that it received a perf_event
								if (ret != 0) {
									action = XDP_ABORTED;
								} else {
									bpf_printk("XDP/BPF Succesfully forwarded function name => %s!", payload);
								}
								goto out;
							}
						}
					}
				}
				optdata++;
			}
		}
	}
   }

out:
	return action;
}

//Basic license just for compiling the object code
char __license[] SEC("license") = "GPL";
