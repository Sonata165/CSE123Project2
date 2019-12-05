/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SR_UTILS_H
#define SR_UTILS_H

// Ethernet header operation
void eth_hdr_set_value(EthernetHeader* hdr, uint8_t* src_mac, uint8_t* dst_mac, uint16_t ethertype);
void eth_copy_addr(unsigned char dst[], unsigned char src[]);
uint8_t* eth_get_src(EthernetHeader* hdr);
uint8_t* eth_get_dst(EthernetHeader* hdr);
uint16_t eth_get_ethertype(EthernetHeader* hdr);

// ARP operation
void arp_hdr_set_value(ArpHeader* arp_hdr, uint16_t protocol_type, uint16_t option, unsigned char src_mac_addr[], uint32_t src_ip_addr, unsigned char dst_mac_addr[], uint32_t dst_ip_addr);
uint16_t arp_get_option(ArpHeader* hdr);

// IP header operation
IpHeader* ip_hdr_set_value(IpHeader* hdr, uint32_t ver, uint32_t hl, uint8_t tos, uint16_t len, uint16_t id, uint16_t off, uint8_t ttl, uint8_t pro, uint32_t src, uint32_t dst);
uint32_t in_addr_to_ip(struct in_addr addr);
uint16_t ip_cksum(IpHeader* hdr);
uint32_t ip_get_hl(IpHeader* hdr);
uint32_t ip_get_v(IpHeader* hdr);
uint8_t ip_get_tos(IpHeader* hdr);
uint16_t ip_get_len(IpHeader* hdr);
uint16_t ip_get_id(IpHeader* hdr);
uint16_t ip_get_off(IpHeader* hdr);
uint8_t ip_get_ttl(IpHeader* hdr);
uint8_t ip_get_pro(IpHeader* hdr);
uint16_t ip_get_sum(IpHeader* hdr);
uint32_t ip_get_src(IpHeader* hdr);
uint32_t ip_get_dst(IpHeader* hdr);

// ICMP shared operation
uint16_t icmp_cksum(void* hdr);

// ICMP T3 operation
void icmp_t3_hdr_set_value(IcmpHeaderT3* hdr, uint8_t code, IpHeader* ip_hdr, uint8_t* data);

// ICMP T8 operation
void icmp_t8_hdr_set_value(IcmpHeaderT8* hdr, uint32_t len, uint8_t type, uint16_t identifier, uint16_t seqnum);
uint16_t icmp_t8_cksum(IcmpHeaderT8* hdr, uint32_t len);
uint16_t icmp_t8_get_identifier(IcmpHeaderT8* hdr);
uint16_t icmp_t8_get_seqnum(IcmpHeaderT8* hdr);

// ICMP T11 operation
void icmp_t11_hdr_set_value(IcmpHeaderT11* hdr, IpHeader* ip_hdr, uint8_t* data);

// Print Functions
void print_addr_eth(uint8_t* addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);
void print_hdr_eth(uint8_t* buf);
void print_hdr_ip(uint8_t* buf);
void print_hdr_icmp(uint8_t* buf);
void print_hdr_arp(uint8_t* buf);
void print_hdrs(uint8_t* buf, uint32_t length);



#endif /* -- SR_UTILS_H -- */
