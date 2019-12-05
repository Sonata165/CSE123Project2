/* This file defines an ARP cache, which is made of two structures: 
    1. an ARP request queue
    2. ARP cache entries. 

   The ARP request queue holds data about an outgoing ARP cache request 
   and the packets that are waiting on a reply to that ARP cache request. 

   The ARP cache entries hold IP->MAC mappings and are timed out every SR_ARPCACHE_TO seconds.

   Pseudocode for use of these structures follows.


   Since send_arp_request as defined in the comments above could destroy your
   current request, make sure to save the next pointer before calling
   send_arp_request when traversing through the ARP requests linked list.
 */

#ifndef SR_ARPCACHE_H
#define SR_ARPCACHE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"
// #include "sr_router.h"

#define SR_ARPCACHE_SZ    100  
#define SR_ARPCACHE_TO    15.0

/**
 * A kind of format of packet, will be used in ARP request queue.
 */
typedef struct sr_packet {
    uint8_t* buf;               /* A raw Ethernet frame, presumably with the dest MAC empty */
    unsigned int len;           /* Length of raw Ethernet frame */
    char* iface;                /* The outgoing interface */
    struct sr_packet* next;
} PacketInReq;

/**
 * A node in ARP request queue. 
 */
typedef struct sr_arpreq {
    uint32_t ip;                // whose MAC this requst want to know
    time_t sent;                /* Last time this ARP request was sent. You 
                                   should update this. If the ARP request was 
                                   never sent, will be 0. */
    uint32_t times_sent;        // Number of times this request was sent. You should update this. 
    PacketInReq* packets;  /* List of pkts waiting on this req to finish */
    uint8_t* req_pkt;
    struct sr_arpreq* next; // Next arp request
} ArpReq;

/**
 * An entry in ARP cache.
 */
typedef struct sr_arpentry {
    unsigned char mac[6]; 
    uint32_t ip;                /* IP addr in network byte order */
    time_t added;         
    int valid;
} ArpEntry;

/**
 * ARP Cache, the core data structure here.
 */
typedef struct sr_arpcache {
    ArpEntry entries[SR_ARPCACHE_SZ]; // ARP Entries
    ArpReq* requests;                 // ARP Request queue

    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
} ArpCache;

/**
 * Checks if an IP->MAC mapping is in the cache. IP is in network byte order. 
 * You must free the returned structure if it is not NULL. 
 * Parameters:
 *   cache - a arp cache
 *   ip - the ip to be checked
 * Returns:
 *   The ARP entry correspond to the given IP addr.
 *   NULL if find nothing.
 */
ArpEntry* sr_arpcache_lookup(ArpCache* cache, uint32_t ip);


ArpReq* sr_arpcache_queuereq(ArpCache* cache,
                            uint32_t ip,
                            uint8_t* packet,               /* borrowed */
                            unsigned int packet_len,
                            char *iface);

/** 
 * This method performs two works when receiving an ARP reply:
 * 1) Looks up this IP in the request queue. If it is found, returns a pointer
 *    to the sr_arpreq with this IP. Otherwise, returns NULL.
 * 2) Inserts this IP to MAC mapping in the cache, and marks it valid.
 * 
 * Parameters:
 *   cache - the ARP cache
 *   mac - the mac addr we just got replied
 *   ip - the ip of the mac addr
 * Returns:
 *   The ArpReq who wants to use this new ARP entry.
 */
ArpReq* sr_arpcache_insert(ArpCache* cache,
                            unsigned char* mac,
                            uint32_t ip);

/**
 * Frees all memory associated with this arp request entry. If this arp request
 * entry is on the arp request queue, it is removed from the queue. 
 * 
 * Parameters:
 *   cache - the ARP cache
 *   entry - the ARP request you want to remove. Can be inside or outside the request queue.
 */
void sr_arpreq_destroy(ArpCache* cache, ArpReq* entry);

/** 
 * Prints out the ARP table. 
 */
void sr_arpcache_dump(ArpCache* cache);

void sr_arpcache_sweepreqs(Router* sr);
void send_arp_request(Router* sr, ArpReq* req);
void handle_arp_reply(struct sr_instance* sr, uint8_t* packet,
    unsigned int len, char* interface_name);

void print_arp_cache(ArpCache* cache);

/*----------DON'T TOUCH--------------*/
/* You shouldn't have to call these methods--they're already called in the
   starter code for you. */
/* a constructor */
int   sr_arpcache_init(ArpCache* cache);
/* a destructor */
int   sr_arpcache_destroy(ArpCache* cache);
/* a cleanup thread times out cache entries every 15 seconds. */
void *sr_arpcache_timeout(void *cache_ptr);

#endif

