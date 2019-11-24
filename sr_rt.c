#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Seems can read a routing(forwarding) table from a file.
 * I guess it's the most useful function in this file.
 * Parameters:
 *   sr - a router
 *   filename - rtable's filename
 * Returns:
 *   0 if success.
 *   -1 otherwise.
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr, const char* filename)
{
    FILE* fp;
    char line[BUFSIZ];
    char dest[32];
    char gw[32];
    char mask[32];
    char iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if (access(filename, R_OK) != 0) {
        perror("access");
        return -1;
    }

    fp = fopen(filename, "r");

    while (fgets(line, BUFSIZ, fp) != 0) {
        sscanf(line, "%s %s %s %s", dest, gw, mask, iface);
        if (inet_aton(dest, &dest_addr) == 0) {
            fprintf(stderr,
                "Error loading routing table, cannot convert %s to valid IP\n",
                dest);
            return -1;
        }
        if (inet_aton(gw, &gw_addr) == 0) {
            fprintf(stderr,
                "Error loading routing table, cannot convert %s to valid IP\n",
                gw);
            return -1;
        }
        if (inet_aton(mask, &mask_addr) == 0) {
            fprintf(stderr,
                "Error loading routing table, cannot convert %s to valid IP\n",
                mask);
            return -1;
        }
        if (clear_routing_table == 0) {
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, iface);
    } /* -- while -- */

    return 0; /* -- success -- */
}

/*---------------------------------------------------------------------
 * Seems can add an entry to the routing table.
 * Parameters:
 *   sr - a router
 *   dest - dst network IP addr
 *   mask - describe a dst network ID together with dest
 *   gw - next hop's IP addr
 *   if_name - through which interface can get to the next hop
 *---------------------------------------------------------------------*/
void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
    struct in_addr gw, struct in_addr mask, char* if_name)
{
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    /* -- empty list special case -- */
    if (sr->routing_table == 0) {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface, if_name, sr_IFACE_NAMELEN);

        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while (rt_walker->next) {
        rt_walker = rt_walker->next;
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface, if_name, sr_IFACE_NAMELEN);

}

/*---------------------------------------------------------------------
 * Print out forwarding table
 * Parameters:
 *   sr - a router
 *---------------------------------------------------------------------*/
void sr_print_routing_table(struct sr_instance* sr)
{
    struct sr_rt* rt_walker = 0;

    if (sr->routing_table == 0) {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("Destination\tGateway\t\tMask\tIface\n");

    rt_walker = sr->routing_table;

    sr_print_routing_entry(rt_walker);
    while (rt_walker->next) {
        rt_walker = rt_walker->next;
        sr_print_routing_entry(rt_walker);
    }

}

/*---------------------------------------------------------------------
 * Print out an entry in forwarding table.
 * Parameters:
 *   entry - an entry in a forwarding table.
 *---------------------------------------------------------------------*/
void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    printf("%s\t\t", inet_ntoa(entry->dest));
    printf("%s\t", inet_ntoa(entry->gw));
    printf("%s\t", inet_ntoa(entry->mask));
    printf("%s\n", entry->interface);

}

/**
 * Perform Longest prefix match to find next hop and corresponding 
 * outgoing interface.
 * HINT: Dont Forget To Do Defensive Copy!
 * Parameters:
 *   dst_ip: the destination IP addr.
 * Returns:
 *   The corresponding rtable entry.
 *   NULL if nothing found.
 */
RTableEntry* lookup_rtable(RTable* rtable, uint32_t dst_ip)
{
    RTableEntry* p = NULL;
    for (p = rtable; p != NULL; p = p->next){
        uint32_t ip_value = in_addr_to_ip(p->dest);
        if (ip_value == dst_ip)
            return p;
    }
    return NULL;
}
