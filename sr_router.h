/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_rt.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
typedef struct sr_if Interface;
typedef struct sr_rt RTable;

/**
 * Structure of an Ethernet Frame inside the router
 */
typedef struct packet_t {
    uint8_t* buf;           /* A raw Ethernet frame, presumably with the dest MAC empty */
    unsigned int len;           /* Length of raw Ethernet frame */
    char* in_iface;
    char* out_iface;
    struct packet_t* next;
} Packet;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 * -------------------------------------------------------------------------- */
typedef struct sr_instance {
    /* Required by the framework */
    int sockfd; /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    pthread_attr_t attr;
    FILE* logfile;

    /* Useful Attributes */
    uint8_t if_num; // The number of interfaces
    Interface* if_list; /* list of interfaces */
    RTable* routing_table; /* routing table */
    struct sr_arpcache cache; /* ARP cache */

    /* Used for scheduling */
    Packet* que[16][16]; // queues' head of each interface.
    pthread_mutex_t lock; // Lock used for pthreads
} Router;



/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* sr /* borrowed */,
                    uint8_t* buf /* borrowed */,
                    unsigned int len,
                    const char* iface /* borrowed */);
int sr_connect_to_server(struct sr_instance*, unsigned short, char*);
int sr_read_from_server(struct sr_instance*);
void send_icmp_type3(uint8_t code, struct sr_instance* sr, uint8_t* packet,
        unsigned int len, char* interface_name);
void send_icmp_type11(struct sr_instance* sr, uint8_t* packet, unsigned int len,
        char* interface_name);

/* -- sr_router.c -- */
void sr_init(struct sr_instance*);
void handle_packet(struct sr_instance*, uint8_t*, unsigned int, char*);
void handle_arp_packet(struct sr_instance* sr, uint8_t* packet,
    unsigned int len, char* interface);
void handle_ip_packet(struct sr_instance* sr, uint8_t* packet,
    unsigned int len, char* interface);
void handle_icmp_packet(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, char* interface_name);
void* schedule(void* sr);
void que_print(Router* sr);
void que_append(Packet** hdr_ptr, Packet* packet);
Packet* que_pop(Packet** hdr_ptr);
void sr_buffer_packet(Router* sr, uint8_t* buf, unsigned int len, char* in_iface_name,
        char* out_iface_name);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance*, const char*);
void sr_set_ether_ip(struct sr_instance*, uint32_t);
void sr_set_ether_addr(struct sr_instance*, const unsigned char*);
void sr_print_if_list(struct sr_instance*);

#endif /* SR_ROUTER_H */
