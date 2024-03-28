#ifndef UTILS_H
#define UTILS_H

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * Copies src_mac to dest_mac. Easier to read than "memcpy",
 * which always requires the size.
 */
void mac_copy(uint8_t *dest_mac, const uint8_t *src_mac);




#endif /* UTILS_H */
