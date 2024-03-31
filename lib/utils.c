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


int get_mask_ones_cnt(uint32_t ip_mask) {
    int mask_ones_cnt = 0;
    int shift_order = 31;

    while (1) {
        int curr_bit = (ip_mask >> shift_order) & 1;

        if (curr_bit == 0) {
            return mask_ones_cnt;
        }

        mask_ones_cnt++;

        if (shift_order == 0) {
            return mask_ones_cnt;
        }

        shift_order--;
    }
}
