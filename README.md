Link: http://cseweb.ucsd.edu/classes/fa17/cse123-a/project.html  
Github: https://github.com/ucsd-cse123-fa2019/project2-Sonata165

# Project 2
- name: Longshen Ou
- ID: U08422808

## 1. Design Logic
Here's the introduction of the working logic of my router:

```
receved packet P
check length(P), if smaller than sizeof(EthernetHeader), drop it
if P is arp:
    check if length(P) larger than minimum ARP packet
    if P is arp request:
        construct a arp reply
        send back
    elif P is arp reply:
        find relevant entry in ARP request queue 
        for each packet in the request, modify the ethernet header
        send all the packets here.
        update ARP cache
elif P is ip:
    check if length(P) larger than minimum IP packet
    check IP checksum
    if for me:
        check if length(P) larger than minimum ICMP type8 packet
        check ICMP checksum
        if it's ICMP echo req:  # impossible to be echo reply,
                                # because a router can't ping others)
            send ICMP echo reply
        if it's TCP/UDP:
            send ICMP port unreachable
    else :  # need forwarding
        update TTL
        Check TTL
        update checksum
        LPM lookup rtable
        if no match:
            send ICMP net unreachable back
        else
            Check ARP cache
            if match:
                modify ethernet header
                forward packet
            else :
                send ARP request
                >5 send back ICMP host unreachable
```

## 2. sr_protocol.h
The structures of all header's (Ethernet, IP, ARP, ICMP t3/t8/t11) are defind here, so do the constants and enumerate types used by these headers.

## 3. sr_router.c / sr_router.h

### handle_packet()
Method "handle_packet" will be invoked each time the router received a packet. So I implement the router's working logic here. It control the outer loop of section "Design Logic", and delegate the work of handling IP and ARP packets to the following functions.

### handle_arp_packet()
Handle ARP packets received.
```
    check if length(P) larger than minimum ARP packet
    if P is arp request:
        construct a arp reply
        send back
    elif P is arp reply:
        find relevant entry in ARP request queue 
        for each packet in the request, modify the ethernet header
        send all the packets here.
        update ARP cache
```

### handle_ip_packet()
Handle IP packets. The working procedure is as follow:
```
    check if length(P) larger than minimum IP packet
    check IP checksum
    if for me:
        check if length(P) larger than minimum ICMP type8 packet
        check ICMP checksum
        if it's ICMP echo req:  # impossible to be echo reply,
                                # because a router can't ping others)
            handle_icmp_packet()
        if it's TCP/UDP:
            send ICMP port unreachable
    else :  # need forwarding
        update TTL
        Check TTL
        update checksum
        LPM lookup rtable
        if no match:
            send ICMP net unreachable back
        else
            Check ARP cache
            if match:
                modify ethernet header
                forward packet
            else :
                send ARP request
                >5 send back ICMP host unreachable
```

### handle_icmp_packet()
Handle received ICMP echo request packet.

The structure of a router is defined in sr_router.h

## 4. sr_util.c / sr_util.h

A lot of tool functions including comopute IP and ICMP checksum, print functions, copy function, and getters/setters. I wrote getters and setters for each kind of header, in order to keep away from mixing up where to use hton/ntoh and where not to use them. 

## 5. sr_arpcache.c / sr_arpcache.h

The structure of ARP cache are defined in sr_arpcache.h. Operations on ARP cache are implemented in sr_arpcache.c.

### sr_arpcache_sweepreqs()
Every incoming packet which need to send ARP request before forwarding, would be saved in a queue. This function is invoked every second to check this queue, and apply send_arp_request() for each entry.

### send_arp_request()
Send ARP request packet in an arp request queue entry. If an entry doesn't have an ARP request, construct one for it. Check if the times of send reaches 5. If not, send ARP request packet. After sending it, increase "times_send" by 1. If it's larger or eaqual than 5, remove the entry from the queue, send ICMP host unerachable back.

## 6. sr_rt.c / sr_rt.h

The structure of routing table are defined in rt.h. Operations on routing table are implemented in rt.c.

### lookup_rtable()
Perform Longest Prefix Match to the destination IP of incoming packet to entries in the routing table.  
If no entry have same prefix as dst, return the entry which has 0.0.0.0/0 as network addr.

## 7. sr_if.c / sr_if.h

The structure of an Interface in router and operations on it are defined here. 

### sr_get_interface()
The most useful function in this file. Get the Interface instance according to the name provided.

## 8. sr_vns_comm.c

Many operation on the router and overall processing are defined here. In order to make sending ICMP packet easier, I add two new function "send_icmp3_packet()" and "send_icmp11_packet" here to wrap the process of construct an ICMP packet and send them. 