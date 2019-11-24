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
 * Method: sr_init(void)
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
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/**
 * Method: sr_handlepacket(uint8_t* p,char* interface)
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
void sr_handlepacket(struct sr_instance* sr, uint8_t* packet,
    unsigned int len, char* interface_name)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface_name);

    printf("*** -> Received packet of length %d \n", len);

    /* fill in code here */
    fprintf(stderr, "*** -> Received packet of length %d \n", len);
    print_hdrs(packet, len);
    uint16_t type = ethertype(packet);
    if (type == ethertype_arp) {
        handle_arp_packet(sr, packet, len, interface_name);
    }
    else if (type == ethertype_ip) {
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
 *   len - the length of the Frame
 *   interface - incoming interface, where the Frame come from
 */
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet,
    unsigned int len, char* interface_name)
{
    /* Check length */
    int min_length = sizeof(EthernetHeader);
    if (len < min_length) {
        fprintf(stderr, "Invalid Ethernet header (ARP) length: %d\n", len);
        return ;
    }

    /* TODO Try to save MAC addr of the src of the packet */
    EthernetHeader* eth_hdr = (EthernetHeader*)packet;
    unsigned char new_mac[ETHER_ADDR_LEN]; // MAC of the src of the incoming packet.
    memcpy(new_mac, eth_hdr->src_mac_addr, ETHER_ADDR_LEN);
    //TODO

    /* Get MAC addr of this interface */
    Interface* interface = sr_get_interface(sr, interface_name);
    unsigned char my_addr[ETHER_ADDR_LEN];
    memcpy(my_addr, interface->addr, ETHER_ADDR_LEN);
    
    /* Get ARP type (arp option) */
    min_length += sizeof(ArpHeader);
    if (len < min_length) {
        fprintf(stderr, "Invalid ARP header length: %d\n", len);
        return ;
    }
    ArpHeader* arp_hdr = (ArpHeader*)(packet + sizeof(EthernetHeader));
    uint16_t arp_type = get_arp_type(arp_hdr);

    /* CAUTION! I didn't construct new packets here, which MAY lead to problems! */
    if (arp_type == arp_op_request){
        /* Modify ARP header */
        arp_hdr->arp_option = htons(arp_op_reply);
        copy_eth_addr(arp_hdr->src_mac_addr, my_addr);
        copy_eth_addr(arp_hdr->dst_mac_addr, new_mac);
        arp_hdr->dst_ip_addr = arp_hdr->src_ip_addr;
        arp_hdr->src_ip_addr = interface->ip;

        /* Modify Ethernet header */
        copy_eth_addr(eth_hdr->src_mac_addr, my_addr);
        copy_eth_addr(eth_hdr->dst_mac_addr, new_mac);

        // print_hdrs(packet, len);
        /* Send back */
        sr_send_packet(sr, packet, len, interface_name);
    }
    else if (arp_type == arp_op_reply){
        handle_arp_reply(sr, packet, len, interface_name);
    }
    else {
        fprintf(stderr, "Invalid ARP op code: %d\n", arp_type);
    }
}

/**
 * Handle IP packet.
 */
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, char* interface_name)
{
    fprintf(stderr, "Handle IP Packet! (TODO) \n");
    IpHeader* ip_hdr = (IpHeader*)(packet + sizeof(EthernetHeader));

    Interface* interface = sr_get_interface(sr, interface_name);
    if (ip_hdr->ip_dst == interface->ip){ // The packet is for this router
        if (ip_hdr->ip_pro == ip_protocol_icmp){ // If it's a ICMP packet
            IcmpHeader* icmp_hdr = (IcmpHeader*)(packet + sizeof(EthernetHeader) + sizeof(IpHeader));
            if (icmp_hdr->icmp_type == ECHO_MSG_TYPE){ // echo message
                // TODO send echo reply!
            }
            else if (icmp_hdr->icmp_type == ECHO_REPLY_TYPE){ // echo reply
                fprintf(stderr, "shit!\n");
            }
        }
    }
    else { // Not for this router, need forwarding.
        printf("\n");
    }
}
