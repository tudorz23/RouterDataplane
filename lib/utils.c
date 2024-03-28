#include "utils.h"

void mac_copy(uint8_t *dest_mac, const uint8_t *src_mac) {
    memcpy(dest_mac, src_mac, 6 * sizeof(uint8_t));
}
