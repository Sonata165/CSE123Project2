/**********************************************************************
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/**
 * Scope:  Global
 *
 * Parameters:
 *   sr - a router
 *   packet - a pointer pointing to the input Ethernet Frame
 *   len - the length of the Frame
 *   interface - incoming interface, where the Frame come from
 * 
 * This method is called each time the router receives a packet on the
 * interface. The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 */
void handle_packet(struct sr_instance* sr, 
                    uint8_t* packet/* lent */,
                    unsigned int len, 
                    char* interface_name/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface_name);

    printf("*** -> Received packet of length %d \n", len);

    /* Fill in code here */
    fprintf(stderr, "*** -> Received packet of length %d from interface %s \n", 
            len, interface_name);
    print_hdrs(packet, len);

    /* Check Length */
    uint16_t min_length = sizeof(EthernetHeader);
    if (len < min_length) {
        fprintf(stderr, "Invalid Ethernet header length: %d\n", len);
        return ;
    }

    EthernetHeader* eth_hdr = (EthernetHeader*)packet;
    uint16_t type = eth_get_ethertype(eth_hdr);
    if (type == ethertype_arp) {
        fprintf(stderr, "It's an ARP packet!\n");
        handle_arp_packet(sr, packet, len, interface_name);
    }
    else if (type == ethertype_ip) {
        fprintf(stderr, "It's an IP packet!\n");
        handle_ip_packet(sr, packet, len, interface_name);
    }
    else {
        fprintf(stderr, "Invalid packet type: %x\n", type);
    }
}

/**
 * Handle ARP packets.
 * Parameters:
 *   sr - a router
 *   packet - a pointer pointing to the input Ethernet Frame
 *   len - the length of the Ethernet Frame
 *   interface - incoming interface, where the Frame come from
 */
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, char* interface_name)
{
    EthernetHeader* eth_hdr = (EthernetHeader*)packet;
    
    /* Check length */
    uint16_t min_length = sizeof(EthernetHeader) + sizeof(ArpHeader);
    if (len < min_length) {
        fprintf(stderr, "Invalid ARP header length: %d\n", len);
        return ;
    }

    /* TODO: Try to save MAC addr of the src of the packet */
    
    /* Get ARP type (arp option) */
    ArpHeader* arp_hdr = (ArpHeader*)(packet + sizeof(EthernetHeader));
    uint16_t arp_type = arp_get_option(arp_hdr);

    /* CAUTION! I didn't construct new packets here, which MAY lead to problems! */
    if (arp_type == arp_op_request){
        fprintf(stderr, "ARP req!\n");
        unsigned char old_src_mac[ETHER_ADDR_LEN];
        unsigned char old_dst_mac[ETHER_ADDR_LEN];
        eth_copy_addr(old_src_mac, eth_hdr->src_mac_addr);
        Interface* interface = sr_get_interface(sr, interface_name);
        eth_copy_addr(old_dst_mac, interface->addr);

        /* Modify ARP header */
        arp_hdr->arp_option = htons(arp_op_reply);
        eth_copy_addr(arp_hdr->src_mac_addr, old_dst_mac);
        eth_copy_addr(arp_hdr->dst_mac_addr, old_src_mac);
        arp_hdr->dst_ip_addr = arp_hdr->src_ip_addr;
        arp_hdr->src_ip_addr = interface->ip;

        /* Modify Ethernet header */
        eth_copy_addr(eth_hdr->src_mac_addr, old_dst_mac);
        eth_copy_addr(eth_hdr->dst_mac_addr, old_src_mac);

        fprintf(stderr, "Construct ARP reply:\n");
        print_hdrs(packet, len);
        /* Send back */
        sr_send_packet(sr, packet, len, interface_name);
    }
    else if (arp_type == arp_op_reply){
        fprintf(stderr, "ARP reply!\n");
        handle_arp_reply(sr, packet, len, interface_name);
    }
    else {
        fprintf(stderr, "Invalid ARP op code: %d\n", arp_type);
    }
}

/**
 * Handle IP packet.
 * 
 * Parameters:
 *   sr - a router
 *   packet - a pointer pointing to the input Ethernet Frame
 *   len - the length of the Frame
 *   interface - incoming interface, where the Frame come from
 * 
 * HINT: After find next hop IP, you could do following:
 *     entry = arpcache_lookup(next_hop_ip)
 *     if entry:
 *         use next_hop_ip->mac mapping in entry to send the packet
 *         free entry
 *     else:
 *         req = arpcache_queuereq(next_hop_ip, packet, len)
 *         send_arp_request(req)
 */
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, 
        char* interface_name)
{
    EthernetHeader* eth_hdr = (EthernetHeader*)packet;

    // Check Length
    uint16_t min_length = sizeof(EthernetHeader) + sizeof(IpHeader);
    if (len < min_length) {
        fprintf(stderr, "Invalid IP header length: %d\n", len);
        return ;
    }

    // Check Checksum
    IpHeader* ip_hdr = (IpHeader*)(packet + sizeof(EthernetHeader));
    uint16_t cksum = ip_cksum(ip_hdr);
    if (cksum != ip_hdr->ip_sum){
        fprintf(stderr, "IP Checksum Error, packet damaged!\n");
        return;
    }

    // Validation, check version, header length, total length
    if (ip_get_v(ip_hdr) != 4 || ip_get_hl(ip_hdr) != 5 
            || ip_get_len(ip_hdr) != len - sizeof(EthernetHeader)){
        fprintf(stderr, "Validation failed!\n");
        return;
    }
    
    /* 2 possibilities: for me / not for me */
    Interface* interface = sr_get_interface(sr, interface_name);
    uint32_t ip_dst = ip_get_dst(ip_hdr);
    if (ip_dst == if_get_ip(interface)){ // For me!
        fprintf(stderr, "It's for me!\n");
        if (ip_hdr->ip_pro == ip_protocol_icmp){ // If it's a ICMP packet
            handle_icmp_packet(sr, packet, len, interface_name);
        }
        else { // non-ICMP packet can't be handled, send ICMP port unreachable
            send_icmp_type3(PORT_UNREACHABLE_CODE, sr, packet, len, interface_name);
        }
    }
    else { // Not for me, need forwarding.
        fprintf(stderr, "Not for me, Need forwarding!\n");

        // TTL check
        if (ip_hdr->ip_ttl <= 1){
            fprintf(stderr, "No enough TTL!\n");
            // Send back ICMP type 11
            send_icmp_type11(sr, packet, len, interface_name);
            return ;
        }

        // TTL & Checksum update
        ip_hdr->ip_ttl -= 1;
        ip_hdr->ip_sum = ip_cksum(ip_hdr);

        RTableEntry* rtable_entry = lookup_rtable(sr->routing_table, ip_dst); // Please don't modify this variable!
        if (rtable_entry == NULL){
            // TODO No match! send ICMP net unreachable
            fprintf(stderr, "no match!\n");
            send_icmp_type3(NET_UNREACHABLE_CODE, sr, packet, len, interface_name);
            return;
        }
        uint32_t nexthop_ip = get_nexthop(rtable_entry);
        char* out_iface = get_interface_name(rtable_entry);
    
        ArpEntry* arp_entry = sr_arpcache_lookup(&sr->cache, nexthop_ip);
        if (arp_entry != NULL){ // ARP hit
            fprintf(stderr, "ARP HIT!\n");

            // Modify the Ethernet header
            Interface* iface = sr_get_interface(sr, out_iface);
            eth_copy_addr(eth_hdr->src_mac_addr, iface->addr);
            eth_copy_addr(eth_hdr->dst_mac_addr, arp_entry->mac);

            /* forward packet */
            sr_send_packet(sr, packet, len, out_iface);

            fprintf(stderr, "Forwarding packet from interface %s:\n", out_iface);
            print_hdrs(packet, len);
        }
        else {
            fprintf(stderr, "No ARP cache!\n");
            ArpReq* req = sr_arpcache_queuereq(&sr->cache, nexthop_ip, packet, len, out_iface);
            send_arp_request(sr, req);
        }
    }
}

/**
 * Handle ICMP type 8 (echo msg) or 0 (echo reply) packet.
 * Parameters:
 *   sr - a router
 *   packet - a pointer pointing to the input Ethernet Frame
 *   len - the length of the Frame
 *   interface - incoming interface, where the Frame come from
 */
void handle_icmp_packet(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, char* interface_name)
{
    EthernetHeader* eth_hdr = (EthernetHeader*)packet;
    IpHeader* ip_hdr = (IpHeader*)(packet + sizeof(EthernetHeader));

    /* Check Length */
    uint16_t min_length = sizeof(EthernetHeader)+sizeof(IpHeader)+sizeof(IcmpHeaderT8);
    if (len < min_length){
        fprintf(stderr, "Invalid ICMP ECHO packet length: %d\n", len);
        return ;
    }

    /* Check Checksum */
    IcmpHeaderT8* icmp_hdr = (IcmpHeaderT8*)(packet + sizeof(EthernetHeader) + sizeof(IpHeader));
    uint32_t icmp_len = len - sizeof(EthernetHeader) - sizeof(IpHeader);
    uint16_t cksm = icmp_t8_cksum(icmp_hdr, icmp_len);
    if (cksm != icmp_hdr->icmp_sum){
        fprintf(stderr, "ICMP Checksum Error, packet damaged!\n");
        return;
    }

    if (icmp_hdr->icmp_type == ECHO_MSG_TYPE){ // echo message
        fprintf(stderr, "icmp echo message received!\n");
        // Construct echo reply!
        uint8_t* buf = (uint8_t*)malloc(len);

        // Copy 'data' field in ICMP type 8 header
        memcpy(buf+min_length, packet+min_length, len - min_length);

        // Construct headers
        icmp_t8_hdr_set_value((IcmpHeaderT8*)(buf+sizeof(EthernetHeader)+sizeof(IpHeader)),
                icmp_len, ECHO_REPLY_TYPE, 
                icmp_t8_get_identifier(icmp_hdr), icmp_t8_get_seqnum(icmp_hdr));
        ip_hdr_set_value((IpHeader*)(buf+sizeof(EthernetHeader)), 4, 5, ip_get_tos(ip_hdr), 
                ip_get_len(ip_hdr), ip_get_id(ip_hdr), ip_get_off(ip_hdr), 64, ip_protocol_icmp, 
                ip_get_dst(ip_hdr), ip_get_src(ip_hdr));
        eth_hdr_set_value((EthernetHeader*)buf, eth_get_dst(eth_hdr), eth_get_src(eth_hdr),
                eth_get_ethertype(eth_hdr));

        // Debug
        fprintf(stderr, "ICMP echo constructed: \n");
        print_hdrs(buf, len);

        sr_send_packet(sr, buf, len, interface_name);
    }
    else if (icmp_hdr->icmp_type == ECHO_REPLY_TYPE){ // echo reply
        fprintf(stderr, "ECHO REPLY RECEIVED!\n");
    }
}




