#include "arp.h"
#include <string.h>
#include <netinet/in.h>


arp_packet_queue *init_packet_queue() {
    arp_packet_queue *packet_queue = malloc(sizeof(arp_packet_queue));
    DIE(!packet_queue, "Packet queue malloc failed.");

    packet_queue->entries = queue_create();
    packet_queue->cnt = 0;

    return packet_queue;
}


void send_arp_request(uint8_t *sender_mac, uint32_t sender_ip,
                      uint32_t target_ip, int interface) {
    uint8_t broadcast_mac[6];
    int res = hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_mac);
    DIE(res, "MAC broadcast address parsing failed.");

    char *request_packet = create_arp_packet(sender_mac, broadcast_mac,
                                             sender_ip, target_ip, ARP_OP_REQUEST);

    size_t length = sizeof(struct ether_header) + sizeof (struct arp_header);
    send_to_link(interface, request_packet, length);
    free(request_packet);
}


void send_arp_reply(uint8_t *sender_mac, uint8_t *target_mac,
                    uint32_t sender_ip, uint32_t target_ip,
                    int interface) {
    char *reply_packet = create_arp_packet(sender_mac, target_mac, sender_ip,
                                           target_ip, ARP_OP_REPLY);

    size_t length = sizeof(struct ether_header) + sizeof (struct arp_header);
    send_to_link(interface, reply_packet, length);
    free(reply_packet);
}


void add_packet_in_queue(arp_packet_queue *packet_queue, char *orig_packet,
                         struct route_table_entry *best_route, size_t packet_len) {
    char *new_packet = malloc(packet_len);
    DIE(!new_packet, "Malloc for packet copy failed.");

    memcpy(new_packet, orig_packet, packet_len);

    // Create a new queue entry.
    arp_queue_entry *new_entry = malloc(sizeof(arp_queue_entry ));
    DIE(!new_entry, "Malloc for queue entry failed.");

    new_entry->packet = new_packet;
    new_entry->packet_len = packet_len;
    new_entry->best_route = best_route;

    queue_enq(packet_queue->entries, new_entry);
    packet_queue->cnt += 1;
}


uint8_t *search_addr_in_cache(list arp_cache, uint32_t target_ip) {
    if (!arp_cache) {
        // Cache is empty.
        return NULL;
    }

    list cache_iter = arp_cache;
    while (cache_iter != NULL) {
        arp_cache_entry *entry = (arp_cache_entry*) cache_iter->element;

        if (ntohl(entry->ip) == target_ip) {
            return entry->mac;
        }

        cache_iter = cache_iter->next;
    }

    return NULL;
}


int check_for_broadcast(uint8_t *target_mac) {
    uint8_t broadcast_mac[6];
    int res = hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_mac);
    DIE(res, "MAC broadcast address parsing failed.");

    int cmp_res = memcmp(broadcast_mac, target_mac, 6 * sizeof(uint8_t));

    if (cmp_res == 0) {
        return 1;
    }

    return 0;
}


char *create_arp_packet(uint8_t *sender_mac, uint8_t *target_mac,
                       uint32_t sender_ip, uint32_t target_ip,
                       uint16_t arp_op) {
    char *packet = malloc(sizeof(struct ether_header) + sizeof (struct arp_header));
    DIE(!packet, "ARP packet malloc failed.");

    struct ether_header *eth_hdr = (struct ether_header*) packet;

    mac_copy(eth_hdr->ether_shost, sender_mac);
    mac_copy(eth_hdr->ether_dhost, target_mac);
    eth_hdr->ether_type = htons(ETHER_TYPE_ARP);

    struct arp_header *arp_hdr = (struct arp_header*) (packet + sizeof(struct ether_header));

    arp_hdr->htype = htons(HARDWARE_TYPE_ETH);
    arp_hdr->ptype = htons(ETHER_TYPE_IPV4);
    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->op = htons(arp_op);
    mac_copy(arp_hdr->sha, sender_mac);
    arp_hdr->spa = sender_ip;
    mac_copy(arp_hdr->tha, target_mac);
    arp_hdr->tpa = target_ip;

    return packet;
}


void handle_arp_reply(struct arp_header *arp_hdr, list *arp_cache,
                      arp_packet_queue *packet_queue) {
    add_cache_entry(arp_cache, arp_hdr->spa, arp_hdr->sha);

    int sent_packets_cnt = 0;

    // Iterate the queue and send the packets whose next hop's MAC
    // address has just been received (i.e. look at the IP of each entry)
    for (int i = 0; i < packet_queue->cnt; i++) {
        arp_queue_entry *entry = (arp_queue_entry*) queue_deq(packet_queue->entries);

        if (entry->best_route->next_hop == arp_hdr->spa) {
            // Send the packet.
            uint8_t local_send_mac[6];
            get_interface_mac(entry->best_route->interface, local_send_mac);

            struct ether_header *eth_hdr = (struct ether_header*) entry->packet;
            update_mac_addresses(eth_hdr, arp_hdr->sha, local_send_mac);
            send_to_link(entry->best_route->interface, entry->packet, entry->packet_len);

            free(entry->packet);
            free(entry);

            sent_packets_cnt++;
            continue;
        }

        // If the packet is not sent, re-enqueue it.
        queue_enq(packet_queue->entries, entry);
    }

    packet_queue->cnt -= sent_packets_cnt;
}


void add_cache_entry(list *arp_cache, uint32_t ip, uint8_t *mac) {
    arp_cache_entry *new_entry = malloc(sizeof(arp_cache_entry));
    DIE(!new_entry, "ARP cache entry malloc failed.");

    new_entry->ip = ip;
    mac_copy(new_entry->mac, mac);

    *arp_cache = cons(new_entry, *arp_cache);
}


void send_packet_safely(char *packet, size_t packet_len, uint32_t local_ip,
                        arp_packet_queue *packet_queue, list arp_cache,
                        struct route_table_entry *best_route) {
    int send_interface = best_route->interface;
    uint8_t local_send_mac[6];
    get_interface_mac(send_interface, local_send_mac);

    uint8_t *next_hop_mac = search_addr_in_cache(arp_cache, ntohl(best_route->next_hop));
    if (!next_hop_mac) {
        add_packet_in_queue(packet_queue, packet, best_route, packet_len);

        send_arp_request(local_send_mac, local_ip,
                         best_route->next_hop, send_interface);
        return;
    }

    // If MAC address was found in the cache, send the packet.
    struct ether_header *eth_hdr = (struct ether_header*) packet;
    update_mac_addresses(eth_hdr, next_hop_mac, local_send_mac);
    send_to_link(send_interface, packet, packet_len);
}
