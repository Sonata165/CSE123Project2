/*-----------------------------------------------------------------------------
 * file:  sr_if.h
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handeling interfaces
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_INTERFACE_H
#define sr_INTERFACE_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#include "sr_protocol.h"

typedef struct sr_instance Router;

/* ----------------------------------------------------------------------------
 * struct sr_if
 *
 * An Interface inside a router
 * -------------------------------------------------------------------------- */
typedef struct sr_if {
    char name[sr_IFACE_NAMELEN]; // name
    unsigned char addr[ETHER_ADDR_LEN]; // MAC addr
    uint32_t ip; // IP addr
    uint32_t speed;
    struct sr_if* next;
} Interface;

Interface* sr_get_interface(Router* sr, const char* name);
void sr_add_interface(Router*, const char*);
void sr_set_ether_addr(Router*, const unsigned char*);
void sr_set_ether_ip(Router*, uint32_t ip_nbo);
void sr_print_if_list(Router*);
void sr_print_if(Interface*);

#endif /* --  sr_INTERFACE_H -- */
