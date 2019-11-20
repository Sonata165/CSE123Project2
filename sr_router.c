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
 *
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
    unsigned int len, char* interface)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /* fill in code here */
    print_hdrs(packet, len);
    EthernetHeader* eth_hdr = (EthernetHeader*)packet;
    uint16_t type = ntohs(eth_hdr->ether_type);
    if (type == ethertype_arp) {
        printf("I'm from ARP!\n");
        handle_arp_packet(sr, packet, len, interface);
    }
    else if (type == ethertype_ip) {
        printf("I'm from IP!\n");
        handle_ip_packet(sr, packet, len, interface);
    }
    else {
        fprintf(stderr, "Invalid packet type: %x\n", type);
    }
}

void handle_arp_packet(struct sr_instance* sr, uint8_t* packet,
    unsigned int len, char* interface) {
    /* Check length */
    int min_length = sizeof(EthernetHeader) + sizeof(ArpHeader);
    if (len < min_length) {
        fprintf("Invalid ARP length: %d\n", len);
        continue;
    }
}

void handle_ip_packet(struct sr_instance* sr, uint8_t* packet,
    unsigned int len, char* interface) {

}
