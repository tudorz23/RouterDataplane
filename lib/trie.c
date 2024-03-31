#include "trie.h"
#include "utils.h"


network_trie_node_t *create_trie_node() {
    network_trie_node_t *node = malloc(sizeof(network_trie_node_t ));
    DIE(!node, "Trie node malloc failed.\n");

    node->entry = NULL;
    node->left = NULL;
    node->right = NULL;
    node->final_state = FALSE;

    return node;
}


network_trie_node_t *trie_insert(network_trie_node_t *root, uint32_t ip_prefix,
                                 uint32_t ip_mask) {
    network_trie_node_t *curr_node = root;

    int bits_to_insert = get_mask_ones_cnt(ip_mask);
    int shift_order = 31;

    for (int i = 0; i < bits_to_insert; i++) {
        int curr_bit = (ip_prefix >> shift_order) & 1;

        if (curr_bit == 0) {
            if (curr_node->left == NULL) {
                network_trie_node_t *new_node = create_trie_node();
                curr_node->left = new_node;
            }

            curr_node = curr_node->left;
        } else {
            // curr_bit == 1
            if (curr_node->right == NULL) {
                network_trie_node_t *new_node = create_trie_node();
                curr_node->right = new_node;
            }

            curr_node = curr_node->right;
        }

        shift_order--;
    }

    // Mark the final node as the end of an IP prefix.
    curr_node->final_state = TRUE;

    return curr_node;
}


network_trie_node_t *trie_retrieve(network_trie_node_t *root, uint32_t target_ip) {
    int shift_order = 31;

    network_trie_node_t *curr_node = root;

    // At most 32 iterations (length of an IPv4 address).
    for (int i = 0; i < 32; i++) {
        int curr_bit = (target_ip >> shift_order) & 1;

        if (curr_bit == 0) {
            if (curr_node->left == NULL) {
                if (curr_node->final_state == TRUE) {
                    return curr_node;
                }
                return NULL;

            } else {
                curr_node = curr_node->left;
            }
        } else {
            // curr_bit == 1;
            if (curr_node->right == NULL) {
                if (curr_node->final_state == TRUE) {
                    return curr_node;
                }
                return NULL;

            } else {
                curr_node = curr_node->right;
            }
        }

        shift_order--;
    }

    if (curr_node->final_state == TRUE) {
        return curr_node;
    }

    return NULL;
}
