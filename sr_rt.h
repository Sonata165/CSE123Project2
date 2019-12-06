/*-----------------------------------------------------------------------------
 * Methods and datastructures for handeling the routing table
 *---------------------------------------------------------------------------*/

#ifndef sr_RT_H
#define sr_RT_H

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <stdint.h>
#include <netinet/in.h>
#include <string.h>

#include "sr_if.h"
#include "sr_utils.h"

/* ----------------------------------------------------------------------------
 * Node in the routing table.
 * -------------------------------------------------------------------------- */
typedef struct sr_rt
{
    struct in_addr dest;
    struct in_addr mask; // dest and mask describe a dst network ID together
    struct in_addr gw; // next hop's IP addr
    char   interface[sr_IFACE_NAMELEN]; // through which interface can get to the next hop
    struct sr_rt* next; // next entry
} RTableEntry, RTable;

RTableEntry* rt_copy(RTableEntry* entry);

uint32_t get_nexthop(RTableEntry* entry);
char* rt_get_interface_name(RTableEntry* entry);
uint32_t rt_get_net_addr(RTableEntry* entry);

uint8_t compute_prefix_length(uint32_t bit_string);

int rt_load(struct sr_instance*,const char*);
void rt_add_entry(struct sr_instance*, struct in_addr,struct in_addr, struct in_addr, char*);
RTableEntry* lookup_rtable(RTable* rtable, uint32_t dst_ip);

void rt_print_routing_table(struct sr_instance* sr);
void rt_print_routing_entry(struct sr_rt* entry);


#endif  /* --  sr_RT_H -- */
