#ifndef FORWARDING_H
#define FORWARDING_H

#include "queue.h"
#include "list.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"

#define MAX_RTABLE_LEN 100001


struct route_table {
    struct route_table_entry *entries;
    int size;
    struct network_trie_node *trie_root;
};

typedef struct route_table route_table_t;


/**
 * Initializes the route table entries and the table size. Then inserts
 * all the prefixes in the trie.
 * @param path File to read the entries from
 * @return Allocated route table
 */
route_table_t *init_route_table(const char *path);


/**
 *  Checks whether the destination_mac of the ethernet_header matches
 *  the router's interface MAC address or the broadcast address.
 *  @return 1 if the MAC is valid, 0 otherwise.
 */
int check_destination_validity(const uint8_t* destination_mac,
                               const uint8_t* local_mac);


/**
 * Checks whether the received checksum corresponds to the
 * locally computed one.
 * @return 1 if it does, 0 otherwise.
 */
int authorize_checksum(struct iphdr *ip_hdr);


/**
 * Checks whether the TTL is > 1. If it is, decrements it
 * and updates the checksum.
 * @return 1 for success, 0 otherwise.
 */
int update_ttl(struct iphdr *ip_hdr);


/**
 * LPM algorithm.
 * @param route_table Route table to search into.
 * @param target_ip Target IPv4 address to search a route for (Host order)
 * @return Best route to the machine with target_ip
 */
struct route_table_entry *get_best_route(route_table_t *route_table, uint32_t target_ip);

#endif /* FORWARDING_H */
