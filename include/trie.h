#ifndef TRIE_H
#define TRIE_H

#include "lib.h"
#include "forwarding.h"


struct network_trie_node {
    struct route_table_entry *entry;
    struct network_trie_node *left;  // For next bit 0
    struct network_trie_node *right; // For next bit 1

    // Only the nodes with final_state set on TRUE
    // will have a non-NULL entry.
    enum {
        TRUE,
        FALSE
    } final_state;
};

typedef struct network_trie_node network_trie_node_t;


/**
 * Allocates memory for and returns a new trie node, setting all
 * attributes on NULL and the final_state on FALSE.
 */
network_trie_node_t *create_trie_node();


/**
 * Inserts a new IPv4 prefix in the trie, specifically as many bits
 * from the prefix as the length of the "1" bit sequence in the mask.
 * For every bit of the prefix, if it is a "0", appends it as a left
 * child of the parent node, else appends it as a right child.
 * @param root Root of the trie
 * @param ip_prefix IPv4 prefix to insert in the trie (Host order)
 * @param ip_mask IPv4 mask, to know how many bits of the prefix
 * should be inserted (Host order)
 * @return The last node, marked with final_state as TRUE
 */
network_trie_node_t *trie_insert(network_trie_node_t *root, uint32_t ip_prefix,
                                 uint32_t ip_mask);


/**
 * Traverses the trie, searching for the prefix
 * longest-matching with the target_ip.
 * @param root Root of the trie
 * @param target_ip IPv4 address to search a match for (Host order)
 * @return Final node of the longest-matching path, if there is one
 * and NULL, otherwise
 */
network_trie_node_t *trie_retrieve(network_trie_node_t *root, uint32_t target_ip);

#endif /* TRIE_H */
