#ifndef ICMP_H
#define ICMP_H

#include "protocols.h"
#include "lib.h"
#include "utils.h"
#include "arp.h"
#include "forwarding.h"


/**
 * Creates and sends a packet in accordance with the standard of an
 * ICMP Echo reply.
 * @param ip_hdr The IPv4 header of the Echo request packet
 * @param packet_len Length of the Echo request packet
 */
void create_icmp_reply(struct iphdr *ip_hdr, size_t packet_len, list arp_cache,
                       arp_packet_queue *packet_queue, route_table_t *route_table);


/**
 * Creates and sends a packet in accordance with the standard of an
 * ICMP error message.
 * @param ip_hdr The IPv4 header of the packet that generated the error
 * @param error_type ICMP encoding of the occurred error
 */
void create_icmp_error(struct iphdr *ip_hdr, uint8_t error_type, list arp_cache,
                       arp_packet_queue *packet_queue, route_table_t *route_table);

#endif /* ICMP_H */
