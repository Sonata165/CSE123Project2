#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"

/**
 * Copy a Ethernet mac address from src to dst.
 * Parameters:
 *   dst, can be NULL
 *   src, can be NULL
 */
void eth_copy_addr(unsigned char* dst, unsigned char* src)
{
    if (src != NULL)
        memcpy(dst, src, ETHER_ADDR_LEN);
    else 
        memset(dst, 0xFF, ETHER_ADDR_LEN);
}

/**
 * Copy a ArpHeader mac address from src to dst.
 * Parameters:
 *   dst, can be NULL
 *   src, can be NULL
 */
void arp_copy_mac(unsigned char* dst, unsigned char* src)
{
    if (src != NULL)
        memcpy(dst, src, ETHER_ADDR_LEN);
    else 
        memset(dst, 0, ETHER_ADDR_LEN);
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
 * Parameters
 *   address - IP addr, type: struct in_addr, host byte order
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
 * Parameters:
 *   ip - IP addr, host byte order.
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
 *   addr - struct in_addr form of IP addr
 * Returns:
 *   the uint32_t form of IP addr, HOST BYTE ORDER
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
    IcmpHeaderT11* icmp_hdr = (IcmpHeaderT11*)(buf);
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

    EthernetHeader* eth_hdr = (EthernetHeader*)buf;
    uint16_t ethtype = eth_get_ethertype(eth_hdr);
    print_hdr_eth(buf);

    if (ethtype == ethertype_ip) { /* IP */
        minlength += sizeof(IpHeader);
        if (length < minlength) {
            fprintf(stderr, "Failed to print IP header, insufficient length\n");
            return;
        }

        IpHeader* ip_hdr = (IpHeader*)(buf + sizeof(EthernetHeader));
        print_hdr_ip(buf + sizeof(EthernetHeader));
        uint8_t ip_proto = ip_get_pro(ip_hdr);

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
 * Set the value of ARP's field.
 * Parameters:
 *   hdr - an EthernetHeader
 *   src_mac - MAC addr of src or NULL
 *   dst_mac - MAC addr of dst or NULL
 *   ethertype - ethertype, HOST BYTE ORDER
 */
void arp_hdr_set_value(ArpHeader* arp_hdr, uint16_t protocol_type, uint16_t option, 
        unsigned char src_mac_addr[], uint32_t src_ip_addr, unsigned char dst_mac_addr[], 
        uint32_t dst_ip_addr)
{
    arp_hdr->hardware_type = htons(arp_hrd_ethernet);
    arp_hdr->protocol_type = htons(protocol_type); // CAUSION!
    arp_hdr->h_addr_len = ETHER_ADDR_LEN;
    arp_hdr->p_addr_len = IP_ADDR_LEN;
    arp_hdr->arp_option = htons(option);
    arp_copy_mac(arp_hdr->src_mac_addr, src_mac_addr);
    arp_hdr->src_ip_addr = htonl(src_ip_addr);
    arp_copy_mac(arp_hdr->dst_mac_addr, dst_mac_addr);
    arp_hdr->dst_ip_addr = htonl(dst_ip_addr);
}

/**
 * Perform IP checksum algorithm.
 */
uint16_t ip_cksum(IpHeader* hdr)
{
    uint16_t* buf = (uint16_t*)hdr;
    uint32_t  sum = 0;
    for (int i = 1; i <= 10; i++){
        if (i == 6){
            buf += 1;
        }
        else {
            sum += *buf++;
            if (sum & 0xFFFF0000){
                sum &= 0xFFFF;
                sum++;
            }
        }
    }
    return ~(sum & 0xFFFF);
}

/**
 * Set field value for ICMP Type 11 (Time Exceeded) header.
 * Parameters:
 *   hdr - a ICMP header
 *   ip_hdr - the IP header who have problem
 *   data - the payload of error IP packet
 */
void icmp_t11_hdr_set_value(IcmpHeaderT11* hdr, IpHeader* ip_hdr, uint8_t* data)
{
    hdr->icmp_type = TTL_TYPE;
    hdr->icmp_code = TTL_CODE;
    hdr->unused = 0;
    memcpy(hdr->data, ip_hdr, IP_HDR_SIZE);
    memcpy(hdr->data+IP_HDR_SIZE, data, 8);

    hdr->icmp_sum = icmp_cksum(hdr);
}

/**
 * Set field value for ICMP t8 header.
 * Parameters:
 *   hdr - a ICMP type 8 header
 *   type - ICMP TYPE
 *   identifier - identifier, NETWORK BYTE ORDER
 *   seqnum - sequence number, NETWORK BYTE ORDER
 */
void icmp_t8_hdr_set_value(IcmpHeaderT8* hdr, uint32_t len, uint8_t type, uint16_t identifier, 
        uint16_t seqnum)
{
    hdr->icmp_type = type;
    hdr->icmp_code = ECHO_CODE;
    hdr->icmp_identifier = htons(identifier);
    hdr->icmp_seqnum = htons(seqnum);

    hdr->icmp_sum = icmp_t8_cksum(hdr, len);
}

/**
 * Set field value for IP header.
 * Parameters (ALL HOST BYTE ORDER):
 *   hdr - a IP header
 *   ver - IP version, host order
 *   hl - header length, host order
 *   tos - type of service
 *   len - total length, host order
 *   id - IP id, host order
 *   off - offset field, host order
 *   ttl - time to live
 *   pro - protocol
 *   src - source IP
 *   dst - destination IP
 * Returns:
 *   An ICMP header whose value is set to what were provided.
 */
IpHeader* ip_hdr_set_value(IpHeader* hdr, uint32_t ver, uint32_t hl, uint8_t tos, 
        uint16_t len, uint16_t id, uint16_t off, uint8_t ttl, uint8_t pro, uint32_t src, uint32_t dst)
{
    hdr->ip_v = ver;
    hdr->ip_hl = hl;
    hdr->ip_tos = tos;
    hdr->ip_len = htons(len);
    hdr->ip_id = htons(id);
    hdr->ip_off = htons(off);
    hdr->ip_ttl = ttl;
    hdr->ip_pro = pro;
    hdr->ip_src = htonl(src);
    hdr->ip_dst = htonl(dst);
    
    hdr->ip_sum = ip_cksum(hdr);

    return hdr;
}

/**
 * Perform IP checksum algorithm for ICMP Type 3 or Type 11 header.
 */
uint16_t icmp_cksum(void* hdr)
{
    uint16_t* buf = (uint16_t*)hdr;
    uint32_t  sum = 0;
    for (int i = 1; i <= 18; i++){
        if (i == 2){
            buf += 1;
        }
        else {
            sum += *buf++;
            if (sum & 0xFFFF0000){
                sum &= 0xFFFF;
                sum++;
            }
        }
    }
    return ~(sum & 0xFFFF);
}

uint16_t icmp_t8_cksum(IcmpHeaderT8* hdr, uint32_t len)
{
    uint16_t* buf = (uint16_t*)hdr;
    uint32_t  sum = 0;
    for (int i = 1; i <= len/2; i++){
        if (i == 2){
            buf += 1;
        }
        else {
            sum += *buf++;
            if (sum & 0xFFFF0000){
                sum &= 0xFFFF;
                sum++;
            }
        }
    }
    return ~(sum & 0xFFFF);
}

/**
 * Set the value of EthernetHeader's field.
 * Parameters:
 *   hdr - an EthernetHeader
 *   src_mac - MAC addr of src or NULL
 *   dst_mac - MAC addr of dst or NULL
 *   ethertype - ethertype, HOST BYTE ORDER
 */
void eth_hdr_set_value(EthernetHeader* hdr, uint8_t* src_mac, uint8_t* dst_mac, uint16_t ethertype)
{
    eth_copy_addr(hdr->src_mac_addr, src_mac);
    eth_copy_addr(hdr->dst_mac_addr, dst_mac);
    hdr->ether_type = htons(ethertype);
}

/**
 * Set the value for ICMP Type3 header.
 * Parameters:
 *   hdr - an ICMP type3 header.
 *   code - the ICMP code.
 *   ip_hdr - the IP header of original IP Packet
 *   data - a pointer ponts to the first byte of 'Data' of Original Datagram
 */
void icmp_t3_hdr_set_value(IcmpHeaderT3* hdr, uint8_t code, IpHeader* ip_hdr, uint8_t* data)
{
    hdr->icmp_type = DST_UNREACHABLE_TYPE;
    hdr->icmp_code = code;
    hdr->unused = 0;
    memcpy(hdr->data, ip_hdr, IP_HDR_SIZE);
    memcpy(hdr->data+IP_HDR_SIZE, data, 8);

    hdr->icmp_sum = icmp_cksum(hdr);
}



/* -------------ARP Getter---------------- */

uint16_t arp_get_option(ArpHeader* hdr)
{ return ntohs(hdr->arp_option); }

/* -------------ICMP Getter---------------- */

uint16_t icmp_t8_get_identifier(IcmpHeaderT8* hdr)
{ return ntohs(hdr->icmp_identifier); }

uint16_t icmp_t8_get_seqnum(IcmpHeaderT8* hdr)
{ return ntohs(hdr->icmp_seqnum); }

/* --------IpHeader Getter---------- */

uint32_t ip_get_hl(IpHeader* hdr)
{ return hdr->ip_hl; }

uint32_t ip_get_v(IpHeader* hdr)
{ return hdr->ip_v; }

uint8_t ip_get_tos(IpHeader* hdr)
{ return hdr->ip_tos; }

uint16_t ip_get_len(IpHeader* hdr)
{ return ntohs(hdr->ip_len); }

uint16_t ip_get_id(IpHeader* hdr)
{ return ntohs(hdr->ip_id); }

uint16_t ip_get_off(IpHeader* hdr)
{ return ntohs(hdr->ip_off); }

uint8_t ip_get_ttl(IpHeader* hdr)
{ return hdr->ip_ttl; }

uint8_t ip_get_pro(IpHeader* hdr)
{ return hdr->ip_pro; }

uint16_t ip_get_sum(IpHeader* hdr)
{ return hdr->ip_sum; }

uint32_t ip_get_src(IpHeader* hdr)
{ return ntohl(hdr->ip_src); }

uint32_t ip_get_dst(IpHeader* hdr)
{ return ntohl(hdr->ip_dst); }

/* ---------------EthernetHeader getter-------------- */

uint8_t* eth_get_src(EthernetHeader* hdr)
{ return hdr->src_mac_addr; }

uint8_t* eth_get_dst(EthernetHeader* hdr)
{ return hdr->dst_mac_addr; }

uint16_t eth_get_ethertype(EthernetHeader* hdr)
{ return ntohs(hdr->ether_type); }
