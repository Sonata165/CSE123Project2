#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct sr_ethernet_hdr {
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
    uint8_t dst_mac_addr[ETHER_ADDR_LEN]; /* destination ethernet address */
    uint8_t src_mac_addr[ETHER_ADDR_LEN]; /* source ethernet address */
    uint16_t ether_type; /* packet type ID */
} __attribute__((packed));

/* Ethernet header */
typedef struct sr_ethernet_hdr EthernetHeader;

struct sr_arp_hdr {
    uint16_t hardware_type; /* format of hardware address   */
    uint16_t protocol_type; /* format of protocol address   */
    unsigned char h_addr_len; /* length of hardware address   */
    unsigned char p_addr_len; /* length of protocol address   */
    uint16_t arp_option; /* ARP opcode (command)         */
    unsigned char src_mac_addr[ETHER_ADDR_LEN]; /* sender hardware address      */
    uint32_t src_ip_addr; /* sender IP address            */
    unsigned char dst_mac_addr[ETHER_ADDR_LEN]; /* target hardware address      */
    uint32_t dst_ip_addr; /* target IP address            */
} __attribute__((packed));

/* ARP header */
typedef struct sr_arp_hdr ArpHeader;
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
struct sr_ip_hdr {
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
    uint8_t ip_tos; /* type of service */
    uint16_t ip_len; /* total length */
    uint16_t ip_id; /* identification */
    uint16_t ip_off; /* fragment offset field */
#define IP_RF 0x8000 /* reserved fragment flag */
#define IP_DF 0x4000 /* dont fragment flag */
#define IP_MF 0x2000 /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    uint8_t ip_ttl; /* time to live */
    uint8_t ip_pro; /* protocol */
    uint16_t ip_sum; /* checksum */
    uint32_t ip_src, ip_dst; /* source and dest address */
} __attribute__((packed));


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

uint32_t str_to_ip(char buf[])
{
    char delim[] = ".";
    char tmp[20];
    strcpy(tmp, buf);
    uint32_t t1 = atoi(strtok(tmp, delim));
    uint32_t t2 = atoi(strtok(NULL, delim));
    uint32_t t3 = atoi(strtok(NULL, delim));
    uint32_t t4 = atoi(strtok(NULL, delim));
    printf("%d, %d, %d, %d\n", t1, t2, t3, t4);
    uint32_t ret = (t1 << 24) + (t2 << 16) + (t3 << 8) + t4;
    return ret;
}

int main()
{
    uint32_t ip = 3232236034;
    char ip_str[] = "192.168.2.2";
    // printf("%s\n", ip_str);
    // char* tok = strtok(ip_str, ".");
    // printf("%s\n", tok);
    // printf("%s\n", ip_str);
    // char* tok1 = strtok(NULL, ".");
    // printf("%s\n", tok1);
    // printf("%s\n", ip_str);
    // printf("%s\n", strtok(NULL, "."));
    uint32_t a = str_to_ip(ip_str);
    print_addr_ip_int(a);
    printf("%s\n", ip_str);
}