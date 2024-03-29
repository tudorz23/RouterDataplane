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


void update_mac_addresses(struct ether_header* eth_hdr, const uint8_t *new_dst,
                          const uint8_t *new_src);

#endif /* UTILS_H */
