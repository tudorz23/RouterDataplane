#ifndef FORWARDING_H
#define FORWARDING_H

#include "queue.h"
#include "list.h"
#include "lib.h"
#include "protocols.h"

#define MAX_RTABLE_LEN 100001


struct route_table {
    struct route_table_entry *entries;
    int size;
};

typedef struct route_table route_table_t;


/**
 * Initializes the route table entries and the table size.
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
 * Quicksort compare function for sorting the route table entries
 * decreasingly by the mask length.
 */
int rtable_compare_func(const void *mask1, const void *mask2);


/**
 * Longest Prefix Match algorithm, done inefficiently.
 */
struct route_table_entry *get_best_route(route_table_t *route_table, uint32_t dest_ip);


/**
 * Prints MAC address in string form, with hex numbers.
 * Useful for debugging.
 */
void print_mac(uint8_t* mac_addr);
void print_ip(char *ip_addr);
void print_rtable(struct route_table_entry *route_table, int cnt);
void print_arp_table(struct arp_table_entry *arp_table, int cnt);

#endif /* FORWARDING_H */
