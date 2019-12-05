#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/**
 * This function gets called every second. For each request sent out, we keep
 * checking whether we should resend an request or destroy the arp request.
 * 
 * ARP requests are sent every second until we send 5 ARP requests, then we send 
 * ICMP host unreachable back to all packets waiting on this ARP request. 
 * 
 * void sr_arpcache_sweepreqs(struct sr_instance *sr):
 *     for each request on sr->cache.requests:
 *         send_arp_request(request)
 */
void sr_arpcache_sweepreqs(Router* sr)
{
    ArpReq* req;
    for (req = sr->cache.requests; req != NULL; req = req->next) {
        fprintf(stderr, "Remaining ARP request in queue: ");
        print_addr_ip_int(req->ip);

        send_arp_request(sr, req);
    }
}

/**
 * Send ARP requests.
 * Only do sending after 1s from last send time, and times of sent < 5.
 *
 * HINT:
 * function send_arp_request(req):
 *     if difftime(now, req->sent) > 1.0
 *          if req->times_sent >= 5:
 *              send icmp host unreachable to source addr of all pkts waiting
 *                  on this request
 *              arpreq_destroy(req)
 *          else:
 *              send arp request
 *              req->sent = now
 *              req->times_sent++
 */
void send_arp_request(Router* sr, ArpReq* req)
{
    time_t now = time(NULL);
    if (difftime(now, req->sent) <= 1.0) {
        fprintf(stderr, "Don't push, it not the time.\n");
        return;
    }

    // If ARP request packet hasn't been constructed, construct one.
    if (req->req_pkt == NULL) {
        Interface* interface = sr_get_interface(sr, req->packets->iface);
        uint8_t* buf = (uint8_t*)malloc(sizeof(EthernetHeader) + sizeof(ArpHeader));
        ArpHeader* arp_hdr = (ArpHeader*)(buf + sizeof(EthernetHeader));
        arp_hdr_set_value(arp_hdr, ethertype_ip, arp_op_request, interface->addr,
            if_get_ip(interface), NULL, req->ip);
        EthernetHeader* eth_hdr = (EthernetHeader*)buf;
        eth_hdr_set_value(eth_hdr, interface->addr, NULL, ethertype_arp);
        req->req_pkt = buf;

        //Debug
        fprintf(stderr, "ARP request constructed: \n");
        print_hdrs(req->req_pkt, sizeof(EthernetHeader) + sizeof(ArpHeader));
    }

    if (req->times_sent >= 5) {
        fprintf(stderr, "You are 5, I can't send you again!\n");

        // TODO: Send ICMP host unreachable for every packets relevant to this req
        PacketInReq* pkt;
        for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
            fprintf(stderr, "ifacename: %s\n", req->packets->iface);
            send_icmp_type3(HOST_UNREACHABLE_CODE, sr, req->packets->buf, req->packets->len, req->packets->iface);
        }
        
        sr_arpreq_destroy(&sr->cache, req);
    } else {
        Interface* interface = sr_get_interface(sr, req->packets->iface);
        sr_send_packet(sr, req->req_pkt, ETHER_HDR_SIZE + ARP_HDR_SIZE, interface->name);
        req->sent = now;
        req->times_sent += 1;
        fprintf(stderr, "Now you're sent for %d times\n", req->times_sent);
    }

    // sr_arpcache_dump(&sr->cache);
}

/**
 * Handle ARP reply.
 * The ARP reply processing code should move entries from the ARP request
 * queue to the ARP cache:
 *
 * HINT:  When servicing an arp reply that gives us an IP->MAC mapping
 * req = arpcache_insert(ip, mac)
 * if req:
 *     send all packets on the req->packets linked list
 *     arpreq_destroy(req)
 * 
 * Parameters:
 *   sr - a router
 *   packet - the packet buffer
 *   len - the length of the packet
 *   interface_name - the name of the interface who receives the arp reply
 */
void handle_arp_reply(struct sr_instance* sr, uint8_t* packet,
    unsigned int len, char* interface_name)
{
    ArpHeader* arp_hdr = (ArpHeader*)(packet + sizeof(EthernetHeader));
    ArpReq* req = sr_arpcache_insert(&sr->cache, arp_hdr->src_mac_addr, ntohl(arp_hdr->src_ip_addr));
    PacketInReq* pkt;
    if (req != NULL) { // send reaming packet in the request queue corresponding to that
        for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
            /* Modify Ethernet header of the original packet, then forward it */
            EthernetHeader* eth_hdr = (EthernetHeader*)(pkt->buf);
            eth_copy_addr(eth_hdr->src_mac_addr, arp_hdr->dst_mac_addr);
            eth_copy_addr(eth_hdr->dst_mac_addr, arp_hdr->src_mac_addr);

            /* Forward packet */
            sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);

            // Debug
            fprintf(stderr, "Forwarding packet from interface %s:\n", pkt->iface);
            print_hdrs(pkt->buf, pkt->len);
        }
        sr_arpreq_destroy(&sr->cache, req);
    }
}

/**
 * typedef struct sr_arpcache {
    ArpEntry entries[SR_ARPCACHE_SZ]; // ARP Entries
    ArpReq* requests;                 // ARP Request queue

    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
} ArpCache;
 */
void print_arp_cache(ArpCache* cache)
{
    ArpEntry* entry;
    fprintf(stderr, "---------------PRINT ARPCACHE-------------------\n");
    for (int i = 0; i < SR_ARPCACHE_SZ; i++) {
        entry = &cache->entries[i];
        if (entry != NULL) {
            print_addr_ip_int(entry->ip);
            print_addr_eth(entry->mac);
        }
    }
    ArpReq* p;
    fprintf(stderr, "queue:\n");
    for (p = cache->requests; p != NULL; p = p->next) {
        print_addr_ip_int(p->ip);
    }
    fprintf(stderr, "----------------------------------------------\n");
}

/*------------------DON'T TOUCH CODE BELOW-------------------------*/

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
struct sr_arpentry* sr_arpcache_lookup(struct sr_arpcache* cache, uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry*)malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/**
 * Adds an ARP request to the ARP request queue. If the request is already on
 * the queue, adds the packet to the linked list of packets for this sr_arpreq
 * that corresponds to this ARP request. 
 * The packet argument should not be freed by the caller.
 * 
 * Parameters:
 *   cache - an ARP cache
 *   ip - whose MAC we want to find, NETWORK ORDER
 *   packet - the packet we want to find its dst's MAC addr
 *   packet_len - the length of packet
 *   iface - the name of outgoing interface
 * Returns:
 *   A pointer to the ARP request is returned; it should be freed. The caller
 *   can remove the ARP request from the queue by calling sr_arpreq_destroy. 
 */
struct sr_arpreq* sr_arpcache_queuereq(struct sr_arpcache* cache,
    uint32_t ip,
    uint8_t* packet, /* borrowed */
    unsigned int packet_len,
    char* iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq* req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq*)calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet* new_pkt = (struct sr_packet*)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t*)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char*)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    req->req_pkt = NULL;

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

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
struct sr_arpreq* sr_arpcache_insert(struct sr_arpcache* cache,
    unsigned char* mac,
    uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            } else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/**
 * Frees all memory associated with this arp request entry. If this arp request
 * entry is on the arp request queue, it is removed from the queue. 
 */
void sr_arpreq_destroy(struct sr_arpcache* cache, struct sr_arpreq* entry)
{
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache* cache)
{
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry* cur = &(cache->entries[i]);
        unsigned char* mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache* cache)
{
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache* cache)
{
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void* sr_arpcache_timeout(void* sr_ptr)
{
    struct sr_instance* sr = sr_ptr;
    struct sr_arpcache* cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
