#include "forwarding.h"
#include <netinet/in.h>


route_table_t *init_route_table(const char *path) {
    route_table_t *route_table = malloc(sizeof(route_table_t ));
    DIE(!route_table, "Route table malloc.\n");

    route_table->entries = malloc(MAX_RTABLE_LEN * sizeof(struct route_table_entry));
    DIE(!route_table->entries, "Route table entries malloc failed.\n");

    route_table->size = read_rtable(path, route_table->entries);

    // Insert all the prefixes in the trie.
    route_table->trie_root = create_trie_node();

    for (int i = 0; i < route_table->size; i++) {
        uint32_t ip_prefix = ntohl(route_table->entries[i].prefix);
        uint32_t ip_mask = ntohl(route_table->entries[i].mask);

        network_trie_node_t *final_node = trie_insert(route_table->trie_root,
                                                      ip_prefix, ip_mask);
        final_node->entry = &route_table->entries[i];
    }

    return route_table;
}


int check_destination_validity(const uint8_t* destination_mac, const uint8_t *local_mac) {
    int broadcast = 1;

    for (int i = 0; i < 6; i++) {
        if (destination_mac[i] != 0xff) {
            broadcast = 0;
            break;
        }
    }

    if (broadcast) {
        return 1;
    }

    for (int i = 0; i < 6; i++) {
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
        return 0;
    }

    ip_hdr->check = old_checksum;
    return 1;
}


int update_ttl(struct iphdr *ip_hdr) {
    if (ip_hdr->ttl <= 1) {
        return 0;
    }

    ip_hdr->ttl -= 1;

    // Update checksum.
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

    return 1;
}


struct route_table_entry *get_best_route(route_table_t *route_table, uint32_t target_ip) {
    network_trie_node_t *best_node = trie_retrieve(route_table->trie_root, target_ip);

    if (!best_node) {
        return NULL;
    }

    return best_node->entry;
}
