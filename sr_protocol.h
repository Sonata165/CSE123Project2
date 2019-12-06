/*
 *  Copyright (c) 1998, 1999, 2000 Mike D. Schiffman <mike@infonexus.com>
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

/**
 * sr_protocol.h
 *
 */

#ifndef SR_PROTOCOL_H
#define SR_PROTOCOL_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdint.h>


#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif



/* FIXME
 * ohh how lame .. how very, very lame... how can I ever go out in public
 * again?! /mc
 */

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 2
#endif

#ifndef __BYTE_ORDER
  #ifdef _CYGWIN_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _LINUX_
  #define __BYTE_ORDER __LITTLE_ENDIAN
  #endif
  #ifdef _SOLARIS_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
  #ifdef _DARWIN_
  #define __BYTE_ORDER __BIG_ENDIAN
  #endif
#endif

/**
 * Structure of ICMP Type 3 (Destination Unreachable) packets' header.
 * 36 bytes, NETWORK BYTE ORDER.
 */
struct sr_icmp_t3_hdr {
#define ICMP_T3_SIZE 36 
#define ICMP_T3_DATA_SIZE 28
#define DST_UNREACHABLE_TYPE 3
#define PORT_UNREACHABLE_CODE 3
#define NET_UNREACHABLE_CODE 0
#define HOST_UNREACHABLE_CODE 1
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_sum;
    uint32_t unused;
    uint8_t data[ICMP_T3_DATA_SIZE];
} __attribute__((packed));
typedef struct sr_icmp_t3_hdr IcmpHeaderT3;

/**
 * Structure of a type 11 (Time Exceeded) ICMP header
 * 36 bytes. NETWORK BYTE ORDER.
 */
struct sr_icmp_t11_hdr {
#define ICMP_T11_SIZE 36
#define ICMP_T11_DATA_SIZE 28
#define TTL_TYPE 11
#define TTL_CODE 0
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_sum;
    uint32_t unused;
    uint8_t data[ICMP_T11_DATA_SIZE];
} __attribute__((packed));
typedef struct sr_icmp_t11_hdr IcmpHeaderT11;

/**
 * Structure of a type 8(echo msg) and type 8(echo reply) ICMP header
 * 8 bytes. NETWORK BYTE ORDER.
 * ATTENTION: 'data' field will be treated as payload, so they are not here. 
 * BUT, when we talk to the length of ICMP type 8 header, the length of 'data' will be included.
 */
struct sr_icmp_t8_hdr {
#define ICMP_T8_SIZE 8 // NOT TRUE HEADER LENGTH!
#define ECHO_MSG_TYPE 8
#define ECHO_REPLY_TYPE 0
#define ECHO_CODE 0
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_sum;
    uint16_t icmp_identifier;
    uint16_t icmp_seqnum;
} __attribute__((packed));
typedef struct sr_icmp_t8_hdr IcmpHeaderT8;

/*
 * Structure of an internet header, naked of options.
 * 20 bytes. NETWORK BYTE ORDER.
 */
struct sr_ip_hdr {
#define IP_HDR_SIZE 20 // IP header rsize in byte
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl : 4; /* header length */
    unsigned int ip_v : 4; /* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v : 4; /* version */
    unsigned int ip_hl : 4; /* header length */
#else
#error "Byte ordering ot specified "
#endif
#define IP_ADDR_LEN 4
#define IP_RF 0x8000    /* reserved fragment flag */
#define IP_DF 0x4000    /* dont fragment flag */
#define IP_MF 0x2000    /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    uint8_t ip_tos;     /* type of service */
    uint16_t ip_len;    /* total length */
    uint16_t ip_id;     /* identification */
    uint16_t ip_off;    /* fragment offset field */
    uint8_t ip_ttl;     /* time to live */
    uint8_t ip_pro;     /* protocol */
    uint16_t ip_sum;    /* checksum */
    uint32_t ip_src, ip_dst; /* source and dest address */
} __attribute__((packed));
typedef struct sr_ip_hdr IpHeader;

/*
 * Ethernet packet header prototype.  Too many O/S's define this differently.
 * Easy enough to solve that and define it here.
 * 
 * Every IP packet sent by ethernet protocol will be added an ethernet header.
 * 14 bytes. NETWORK BYTE ORDER.
 */
struct sr_ethernet_hdr {
#define ETHER_HDR_SIZE 14 
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t dst_mac_addr[ETHER_ADDR_LEN];
    uint8_t src_mac_addr[ETHER_ADDR_LEN];
    uint16_t ether_type;
} __attribute__((packed));
typedef struct sr_ethernet_hdr EthernetHeader;

/**
 * ARP header.
 * 28 bytes. NETWORK BYTE ORDER.
 */
struct sr_arp_hdr {
#define ARP_HDR_SIZE 28 
    uint16_t hardware_type; /* hardware type */
    uint16_t protocol_type; /* protocol type, should be IP */
    unsigned char h_addr_len; /* length of hardware address   */
    unsigned char p_addr_len; /* length of protocol address   */
    uint16_t arp_option; /* ARP opcode (command), network byte order */
    unsigned char src_mac_addr[ETHER_ADDR_LEN]; /* sender hardware address      */
    uint32_t src_ip_addr; /* sender IP address, network byte order */
    unsigned char dst_mac_addr[ETHER_ADDR_LEN]; /* target hardware address      */
    uint32_t dst_ip_addr; /* target IP address, network byte order */
} __attribute__((packed));
typedef struct sr_arp_hdr ArpHeader;

/**
 * Code for IpHeader.ip_pro
 */
enum sr_ip_protocol {
    ip_protocol_icmp = 0x0001,
};

/**
 * Code for EthernetHeader.ether_type and ArpHeader.protocol_type.
 */
enum sr_ethertype {
    ethertype_arp = 0x0806, // 2054
    ethertype_ip = 0x0800, // 2048
};

/**
 * Code for arp_option in ARP header.
 */
enum sr_arp_opcode {
    arp_op_request = 0x0001,
    arp_op_reply = 0x0002,
};

/**
 * Code for ArpHeader.hardware type.
 */
enum sr_arp_hrd_fmt {
    arp_hrd_ethernet = 0x0001,
};

#define sr_IFACE_NAMELEN 32

#endif /* -- SR_PROTOCOL_H -- */
