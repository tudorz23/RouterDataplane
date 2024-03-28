#include "arp.h"
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void send_arp_request(uint8_t *sender_mac, uint32_t sender_ip,
                      uint32_t target_ip, int interface) {
    uint8_t broadcast_mac[6];
    int res = hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_mac);
    DIE(!res, "MAC broadcast address parsing failed.");

    char *request_packet = create_arp_packet(sender_mac, broadcast_mac,
                                             sender_ip, target_ip, ARP_OP_REQUEST);

    send_to_link(interface, request_packet, sizeof(request_packet));
    free(request_packet);
}


void send_arp_reply(uint8_t *sender_mac, uint8_t *target_mac,
                    uint32_t sender_ip, uint32_t target_ip,
                    int interface) {
    char *reply_packet = create_arp_packet(sender_mac, target_mac, sender_ip,
                                           target_ip, ARP_OP_REPLY);

    send_to_link(interface, reply_packet, sizeof(reply_packet));
    free(reply_packet);
}

void add_packet_in_queue(queue packet_queue, char *orig_packet, int packet_len) {
    char *new_packet = malloc(packet_len);
    DIE(!new_packet, "Malloc failed.");

    memcpy(new_packet, orig_packet, packet_len);
    queue_enq(packet_queue, new_packet);
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
    DIE(!res, "MAC broadcast address parsing failed.");

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

    arp_hdr->htype = 1; // For Ethernet.
    arp_hdr->ptype = htons(ETHER_TYPE_IPV4);
    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->op = arp_op;
    mac_copy(arp_hdr->sha, sender_mac);
    arp_hdr->spa = sender_ip;
    mac_copy(arp_hdr->tha, target_mac);
    arp_hdr->tpa = target_ip;

    return packet;
}
