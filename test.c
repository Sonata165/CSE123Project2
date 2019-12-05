#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

#define ICMP_T11_DATA_SIZE 28
/**
 * Structure of a type11 ICMP header
 */
struct sr_icmp_t11_hdr {
#define ECHO_MSG_TYPE 8
#define ECHO_REPLY_TYPE 0
    uint8_t icmp_type;
#define ECHO_MSG_CODE 0
#define ECHO_REPLY_CODE 0
    uint8_t icmp_code;
    uint16_t icmp_sum;
    uint32_t unused;
    uint8_t data[ICMP_T11_DATA_SIZE];

} __attribute__((packed));
typedef struct sr_icmp_t11_hdr IcmpHeaderT11;

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
    unsigned int ip_hl : 4; /* header length, only 4 bits, [0, 15] */
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
typedef struct sr_ip_hdr IpHeader;

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

struct
{
    int a : 4;
    int b : 13;
    int c : 1;
} test;

struct
{
    int a : 16;
    int b : 25;

    uint8_t c;
    // char d;
    // uint32_t e;

} test1;

/**
 * The checksum field is the 16 bit one's complement of the one's
 *   complement sum of all 16 bit words in the header.  For purposes of
 *    computing the checksum, the value of the checksum field is zero.
 */
void compute_checksum()
{
}

uint16_t cksum(uint16_t* buf, int len)
{
    uint32_t sum = 0;
    while (len--) {
        sum += *buf++;
        if (sum & 0xFFFF0000) {
            sum &= 0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}

uint16_t shit()
{
    uint32_t a = 2100000000;
    return a;
}

struct sr_icmp_t8_hdr {
#define ICMP_T11_DATA_SIZE 28
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

uint8_t compute_prefix_length(uint32_t bit_string)
{
    uint8_t cnt = 0;
    for (int i = 1; i <= 32; i++){
        if (bit_string & 0x80000000) {
            cnt += 1;
            bit_string = bit_string << 1;
        }
        else
            break;
    }
    return cnt;
}



int main()
{
    uint32_t a = 0xf8bff1dd;
    uint8_t res = compute_prefix_length(a);
    printf("%d\n", res);
}