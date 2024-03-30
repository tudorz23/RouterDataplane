#ifndef ICMP_H
#define ICMP_H

#include "protocols.h"
#include "lib.h"
#include "utils.h"
#include "arp.h"
#include "forwarding.h"


void create_icmp_reply(struct iphdr *ip_hdr, size_t packet_len, list arp_cache,
                       arp_packet_queue *packet_queue, route_table_t *route_table);


void create_icmp_error(struct iphdr *ip_hdr, uint8_t error_type, list arp_cache,
                       arp_packet_queue *packet_queue, route_table_t *route_table);

#endif /* ICMP_H */
