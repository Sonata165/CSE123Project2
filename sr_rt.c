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

int rt_load(struct sr_instance* sr, const char* filename)
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
        rt_add_entry(sr, dest_addr, gw_addr, mask_addr, iface);
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
void rt_add_entry(struct sr_instance* sr, struct in_addr dest,
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
void rt_print_routing_table(struct sr_instance* sr)
{
    struct sr_rt* rt_walker = 0;

    if (sr->routing_table == 0) {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("Destination\tGateway\t\tMask\tIface\n");

    rt_walker = sr->routing_table;

    rt_print_routing_entry(rt_walker);
    while (rt_walker->next) {
        rt_walker = rt_walker->next;
        rt_print_routing_entry(rt_walker);
    }

}

/*---------------------------------------------------------------------
 * Print out an entry in forwarding table.
 * Parameters:
 *   entry - an entry in a forwarding table.
 *---------------------------------------------------------------------*/
void rt_print_routing_entry(struct sr_rt* entry)
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
 *
 * Parameters:
 *   rtable: forwarding table
 *   dst_ip: the destination IP addr, host order.
 * Returns:
 *   A copy of the corresponding rtable entry.
 *   NULL if nothing found.
 */
RTableEntry* lookup_rtable(RTable* rtable, uint32_t dst_ip)
{
    fprintf(stderr, "I'm looking for %u: ", dst_ip);
    print_addr_ip_int(dst_ip);

    uint8_t max_prefix_len = 0;
    RTableEntry* ret = NULL;
    RTableEntry* p = NULL;
    if (dst_ip != 0){
        for (p = rtable; p != NULL; p = p->next){
            uint32_t net_addr = rt_get_net_addr(p);
            uint32_t dst_net_addr = dst_ip & in_addr_to_ip(p->mask);
            print_addr_ip_int(net_addr);
            print_addr_ip_int(dst_net_addr);
            fprintf(stderr, "shit\n");
            uint32_t tmp = ~(dst_net_addr ^ net_addr);
            uint32_t check = compute_prefix_length(tmp);
            fprintf(stderr, "check = %d\n", check);
            uint32_t prefix_len = compute_prefix_length(in_addr_to_ip(p->mask));
            if (check == 32 && prefix_len > max_prefix_len){
                max_prefix_len = prefix_len;
                ret = p;
            }
        }
        if (max_prefix_len == 0){
            fprintf(stderr, "Find No rtable entry!\n");
            return NULL;
        }
    }
    else {
        for (p = rtable; p != NULL; p = p->next){
            if (rt_get_net_addr(p) == 0){
                ret = p;
                break;
            }
        }
    }



    // Debug
    fprintf(stderr, "finally, chose %s\n", ret->interface);

    return rt_copy(ret);
}

/**
 * Get the next hop of this entry.
 * Returns:
 *   the uint32_t form next hop IP.
 */
uint32_t get_nexthop(RTableEntry* entry)
{
    uint32_t ret = in_addr_to_ip(entry->gw);
    return ret;
}

/**
 * Get the outgoing interface name of this entry.
 * Returns:
 *   the outgoing interface name of this entry
 */
char* rt_get_interface_name(RTableEntry* entry)
{
    return entry->interface;
}

/**
 * Get the network addr described by dest and mask together.
 * Returns:
 *   the network addr described by dest and mask together.
 */
uint32_t rt_get_net_addr(RTableEntry* entry)
{
    uint32_t dest = in_addr_to_ip(entry->dest);
    uint32_t mask = in_addr_to_ip(entry->mask);
    uint32_t ret = dest & mask;
    return ret;
}

/**
 * Scope: Local
 * Get the number of consecutive 1s in the beginning of bit_string.
 *
 * Parameters:
 *   bit_string - the binary string to be checked.
 * Returns:
 *   the number of consecutive 1s in the beginning of bit_string
 */
uint8_t compute_prefix_length(uint32_t bit_string)
{
    uint8_t cnt = 0;
    for (int i = 0; i < 32; i++){
        if (bit_string & 0x80000000){
            cnt += 1;
            bit_string = bit_string << 1;
        }
        else
            break;
    }
    return cnt;
}

/**
 * Copy a RTableEntry.
 *
 * Parameters:
 *   entry - the entry to be copied.
 */
RTableEntry* rt_copy(RTableEntry* entry)
{
    RTableEntry* ret = (RTableEntry*)malloc(sizeof(RTableEntry));
    memcpy(ret, entry, sizeof(RTableEntry));
    return ret;
}
