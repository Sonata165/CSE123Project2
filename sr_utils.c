#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"

uint16_t cksum(const void* _data, int len)
{
    const uint8_t* data = _data;
    uint32_t sum;

    for (sum = 0; len >= 2; data += 2, len -= 2)
        sum += data[0] << 8 | data[1];
    if (len > 0)
        sum += data[0] << 8;
    while (sum > 0xffff)
        sum = (sum >> 16) + (sum & 0xffff);
    sum = htons(~sum);
    return sum ? sum : 0xffff;
}

uint16_t ethertype(uint8_t* buf)
{
    EthernetHeader* ehdr = (EthernetHeader*)buf;
    return ntohs(ehdr->ether_type);
}

uint16_t get_arp_type(ArpHeader* hdr)
{
    return ntohs(hdr->arp_option);
}

/**
 * Copy a Ethernet address from src to dst.
 * Parameters:
 *   dst
 *   src
 */
void copy_eth_addr(unsigned char dst[], unsigned char src[])
{
    memcpy(dst, src, ETHER_ADDR_LEN);
}

/**
 * Get the protocol used by this IP packet.
 */
uint8_t ip_protocol(uint8_t* buf)
{
    IpHeader* iphdr = (IpHeader*)(buf);
    return iphdr->ip_pro;
}

/**
 * Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 
 **/
void print_addr_eth(uint8_t* addr)
{
    int pos = 0;
    uint8_t cur;
    for (; pos < ETHER_ADDR_LEN; pos++) {
        cur = addr[pos];
        if (pos > 0)
            fprintf(stderr, ":");
        fprintf(stderr, "%02X", cur);
    }
    fprintf(stderr, "\n");
}

/**
 * Prints out IP address as a string from in_addr 
 */
void print_addr_ip(struct in_addr address)
{
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
        fprintf(stderr, "inet_ntop error on address conversion\n");
    else
        fprintf(stderr, "%s\n", buf);
}

/**
 * Prints out IP address from integer value
 */
void print_addr_ip_int(uint32_t ip)
{
    uint32_t curOctet = ip >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 8) >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 16) >> 24;
    fprintf(stderr, "%d.", curOctet);
    curOctet = (ip << 24) >> 24;
    fprintf(stderr, "%d\n", curOctet);
}

/**
 * Convert struct in_addr to uint32_t.
 * Parameters:
 *   addr - the uint32_t form of IP addr
 * Returns:
 *   struct in_addr form of IP addr
 *   0 if failed.
 */
uint32_t in_addr_to_ip(struct in_addr addr)
{
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, buf, 100) == NULL){
        fprintf(stderr, "inet_ntop error on address conversion\n");
        return 0;
    }
    else {
        char delim[] = ".";
        uint32_t t1 = atoi(strtok(buf, delim));
        uint32_t t2 = atoi(strtok(NULL, delim));
        uint32_t t3 = atoi(strtok(NULL, delim));
        uint32_t t4 = atoi(strtok(NULL, delim));
        uint32_t ret = (t1 << 24) + (t2 << 16) + (t3 << 8) + t4;
        return ret;
    }
}

/**
 * Prints out fields in Ethernet header. 
 */
void print_hdr_eth(uint8_t* buf)
{
    EthernetHeader* ehdr = (EthernetHeader*)buf;
    fprintf(stderr, "ETHERNET header:\n");
    fprintf(stderr, "\tdestination: ");
    print_addr_eth(ehdr->dst_mac_addr);
    fprintf(stderr, "\tsource: ");
    print_addr_eth(ehdr->src_mac_addr);
    fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/** 
 * Prints out fields in IP header.
 */
void print_hdr_ip(uint8_t* buf)
{
    IpHeader* iphdr = (IpHeader*)(buf);
    fprintf(stderr, "IP header:\n");
    fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
    fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
    fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
    fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
    fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

    if (ntohs(iphdr->ip_off) & IP_DF)
        fprintf(stderr, "\tfragment flag: DF\n");
    else if (ntohs(iphdr->ip_off) & IP_MF)
        fprintf(stderr, "\tfragment flag: MF\n");
    else if (ntohs(iphdr->ip_off) & IP_RF)
        fprintf(stderr, "\tfragment flag: R\n");

    fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
    fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
    fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_pro);

    /*Keep checksum in NBO*/
    fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

    fprintf(stderr, "\tsource: ");
    print_addr_ip_int(ntohl(iphdr->ip_src));

    fprintf(stderr, "\tdestination: ");
    print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/**
 * Prints out ICMP header fields 
 */
void print_hdr_icmp(uint8_t* buf)
{
    IcmpHeader* icmp_hdr = (IcmpHeader*)(buf);
    fprintf(stderr, "ICMP header:\n");
    fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
    fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
    /* Keep checksum in NBO */
    fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}

/**
 *  Prints ARP header
 */
void print_hdr_arp(uint8_t* buf)
{
    ArpHeader* arp_hdr = (ArpHeader*)(buf);
    fprintf(stderr, "ARP header\n");
    fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->hardware_type));
    fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->protocol_type));
    fprintf(stderr, "\thardware address length: %d\n", arp_hdr->h_addr_len);
    fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->p_addr_len);
    fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->arp_option));

    fprintf(stderr, "\tsender hardware address: ");
    print_addr_eth(arp_hdr->src_mac_addr);
    fprintf(stderr, "\tsender ip address: ");
    print_addr_ip_int(ntohl(arp_hdr->src_ip_addr));

    fprintf(stderr, "\ttarget hardware address: ");
    print_addr_eth(arp_hdr->dst_mac_addr);
    fprintf(stderr, "\ttarget ip address: ");
    print_addr_ip_int(ntohl(arp_hdr->dst_ip_addr));
}

/**
 *  Prints out Ethernet header and IP/ARP header 
 */
void print_hdrs(uint8_t* buf, uint32_t length)
{
    fprintf(stderr, "-----------------PRINT HEADERS------------------\n");
    /* Ethernet */
    int minlength = sizeof(EthernetHeader);
    if (length < minlength) {
        fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
        return;
    }

    uint16_t ethtype = ethertype(buf);
    print_hdr_eth(buf);

    if (ethtype == ethertype_ip) { /* IP */
        minlength += sizeof(IpHeader);
        if (length < minlength) {
            fprintf(stderr, "Failed to print IP header, insufficient length\n");
            return;
        }

        print_hdr_ip(buf + sizeof(EthernetHeader));
        uint8_t ip_proto = ip_protocol(buf + sizeof(EthernetHeader));

        if (ip_proto == ip_protocol_icmp) { /* ICMP */
            minlength += 4;
            if (length < minlength)
                fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
            else
                print_hdr_icmp(buf + sizeof(EthernetHeader) + sizeof(IpHeader));
        }
    } else if (ethtype == ethertype_arp) { /* ARP */
        minlength += sizeof(ArpHeader);
        if (length < minlength)
            fprintf(stderr, "Failed to print ARP header, insufficient length\n");
        else
            print_hdr_arp(buf + sizeof(EthernetHeader));
    } else {
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
    }
    fprintf(stderr, "------------------------------------------------\n");
}

/**
 * Construct an ARP request according to information given.
 * An ARP request packet only have headers, no payload.
 * 
 * Parameters:
 *   src_mac_addr - the MAC address of the one who want's to send ARP request
 *   src_ip_addr - the IP address of the one who want's to send ARP request
 *   dst_ip_addr - the IP address of the one who you want to know its MAC addr
 * Returns:
 *   (frame, length)
 */
FrameAndLen construct_arp_request(unsigned char src_mac_addr[],
                                uint32_t src_ip_addr,
                                uint32_t dst_ip_addr)
{
    uint8_t len = sizeof(EthernetHeader) + sizeof(ArpHeader);
    uint8_t* buf = (uint8_t*)malloc(len);

    ArpHeader* arp_hdr = (ArpHeader*)(buf + sizeof(EthernetHeader));
    arp_hdr->hardware_type = arp_hrd_ethernet;
    arp_hdr->protocol_type = ethertype_ip; // CAUSION!
    arp_hdr->h_addr_len = ETHER_ADDR_LEN;
    arp_hdr->p_addr_len = IP_ADDR_LEN;
    arp_hdr->arp_option = arp_op_request;
    copy_eth_addr(arp_hdr->src_mac_addr, src_mac_addr);
    arp_hdr->src_ip_addr = src_ip_addr;
    memset(arp_hdr->dst_mac_addr, 0, sizeof(ETHER_ADDR_LEN));
    arp_hdr->dst_ip_addr = dst_ip_addr;

    EthernetHeader* eth_hdr = (EthernetHeader*)buf;
    memset(eth_hdr->dst_mac_addr, 0xFF, sizeof(ETHER_ADDR_LEN));
    copy_eth_addr(eth_hdr->src_mac_addr, src_mac_addr);
    eth_hdr->ether_type = ethertype_arp; // CAUSION!

    FrameAndLen ret;
    ret.frame = buf;
    ret.len = len;
    return ret;
}