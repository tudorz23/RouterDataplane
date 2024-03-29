#include "utils.h"

void mac_copy(uint8_t *dest_mac, const uint8_t *src_mac) {
    memcpy(dest_mac, src_mac, 6 * sizeof(uint8_t));
}


void update_mac_addresses(struct ether_header* eth_hdr, const uint8_t *new_dst,
                          const uint8_t *new_src) {
    for (int i = 0; i < 6; i++) {
        eth_hdr->ether_dhost[i] = new_dst[i];
        eth_hdr->ether_shost[i] = new_src[i];
    }
}

