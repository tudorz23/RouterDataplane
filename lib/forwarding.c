#include "forwarding.h"
#include <netinet/in.h>
#include <arpa/inet.h>

int check_destination_validity(const uint8_t* destination_mac, const uint8_t *local_mac) {
    int broadcast = 1;

    for (int i = 0; i < 5; i++) {
        if (destination_mac[i] != 0xff) {
            broadcast = 0;
            break;
        }
    }

    if (broadcast) {
        return 1;
    }

    for (int i = 0; i < 5; i++) {
        if (destination_mac[i] != local_mac[i]) {
            return 0;
        }
    }

    return 1;
}

int authorize_checksum(struct iphdr *ip_hdr) {
    uint16_t old_checksum = ip_hdr->check;
    ip_hdr->check = 0;
    uint16_t computed_checksum = checksum((uint16_t *) ip_hdr, sizeof(struct iphdr));

    if (htons(computed_checksum) != old_checksum) {
        printf("Wrong checksum.\n");
        return 0;
    }

    ip_hdr->check = old_checksum;
    return 1;
}

int update_ttl(struct iphdr *ip_hdr) {
    if (ip_hdr->ttl <= 1) {
        printf("Time exceeded.\n");
        return 0;
    }

    ip_hdr->ttl -= 1;

    // Update checksum.
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

    return 1;
}

int rtable_compare_func(const void *rtable_entry1, const void *rtable_entry2) {
    uint32_t mask1 = ntohl(((struct route_table_entry *) rtable_entry1)->mask);
    uint32_t mask2 = ntohl(((struct route_table_entry *) rtable_entry2)->mask);

    // To avoid overflow (must return an int).
    if (mask1 > mask2) {
        return -1;
    }

    if (mask1 < mask2) {
        return 1;
    }

    return 0;
}

// TODO: optimize the search algorithm
struct route_table_entry *get_best_route(struct route_table_entry *route_table,
                                       int rtable_size, uint32_t dest_ip) {
    for (int i = 0; i < rtable_size; i++) {
        uint32_t entry_prefix = ntohl(route_table[i].prefix);
        uint32_t entry_mask = ntohl(route_table[i].mask);

        if ((dest_ip & entry_mask) == entry_prefix) {
            return &route_table[i];
        }
    }

    return NULL;
}

char *get_next_hop_mac(struct arp_table_entry *arp_table, int arp_table_size,
                       uint32_t next_hop_ip) {
    for (int i = 0; i < arp_table_size; i++) {
        if (ntohl(arp_table[i].ip) == next_hop_ip) {
            return (char *) arp_table[i].mac;
        }
    }
    return NULL;
}

void print_mac(uint8_t *mac_addr) {
    for (int i = 0; i < 6; i++) {
        printf("%x:", mac_addr[i]);
    }
    printf("\n");
}
void print_ip(char *ip_addr) {
    printf("%s\n", ip_addr);
}
void print_rtable(struct route_table_entry *route_table, int cnt) {
    for (int i = 0; i < cnt; i++) {
        printf("Route table entry #%d: ", i);
        printf("%u %u %u %d\n", route_table[i].prefix,
               route_table[i].next_hop,
               route_table[i].mask,
               route_table[i].interface);
    }
}
void print_arp_table(struct arp_table_entry *arp_table, int cnt) {
    for (int i = 0; i < cnt; i++) {
        printf("ARP table entry#%d: ", i);
        printf("%u ", arp_table[i].ip);
        print_mac(arp_table[i].mac);
    }
}
