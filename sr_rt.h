/*-----------------------------------------------------------------------------
 * Methods and datastructures for handeling the routing table
 *---------------------------------------------------------------------------*/

#ifndef sr_RT_H
#define sr_RT_H

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <netinet/in.h>

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
} RTableEntry;

typedef struct sr_rt RTable;


int sr_load_rt(struct sr_instance*,const char*);
void sr_add_rt_entry(struct sr_instance*, struct in_addr,struct in_addr,
                  struct in_addr, char*);
void sr_print_routing_table(struct sr_instance* sr);
void sr_print_routing_entry(struct sr_rt* entry);


#endif  /* --  sr_RT_H -- */
