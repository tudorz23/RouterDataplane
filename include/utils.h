#ifndef UTILS_H
#define UTILS_H

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protocols.h"


/**
 * Copies src_mac to dest_mac. Easier to read than "memcpy",
 * which always requires the size.
 */
void mac_copy(uint8_t *dest_mac, const uint8_t *src_mac);


/**
 * Updates the source and destination MAC addresses of an Ethernet header.
 */
void update_mac_addresses(struct ether_header* eth_hdr, const uint8_t *new_dst,
                          const uint8_t *new_src);


/**
 * Knowing that an IPv4 mask starts with a sequence of "1" bits and ends
 * with a sequence of "0" bits, counts the number of ones.
 * @param ip_mask Valid IPv4 mask in Host order
 */
int get_mask_ones_cnt(uint32_t ip_mask);

#endif /* UTILS_H */
