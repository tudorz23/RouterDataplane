#ifndef ARP_H
#define ARP_H

#include "queue.h"
#include "list.h"
#include "lib.h"
#include "protocols.h"
#include "utils.h"
#include <netinet/in.h>
#include <arpa/inet.h>


struct arp_cache_entry {
    uint32_t ip;    // Network order
    uint8_t mac[6];
};

typedef struct arp_cache_entry arp_cache_entry;


// Allows for fast access to the next hop of a packet.
struct arp_queue_entry {
    char *packet;
    size_t packet_len;
    struct route_table_entry *best_route;
};

typedef struct arp_queue_entry arp_queue_entry;


struct arp_packet_queue {
    queue entries;
    int cnt;
};

typedef struct arp_packet_queue arp_packet_queue;


/**
 * Initializes the packet queue.
 * @return Dynamically allocated packet queue structure.
 */
arp_packet_queue *init_packet_queue();


/**
 * Sends an ARP request on broadcast, asking for the MAC address of
 * the machine with the target_ip IP address.
 * @param sender_mac MAC address of the machine creating the ARP request
 * @param sender_ip IP of the machine creating the ARP request (Network order)
 * @param target_ip IP of the next hop machine (Network order)
 * @param interface Interface of the sender machine to send the request message
 */
void send_arp_request(uint8_t *sender_mac, uint32_t sender_ip,
                      uint32_t target_ip, int interface);


/**
 * Sends an ARP reply containing sender's own MAC address, as an
 * answer to a previous ARP request on broadcast.
 * @param sender_mac MAC address of the machine creating the ARP reply
 * @param target_mac MAC address of the machine that previously asked
 * for sender's MAC address
 * @param sender_ip IP of the machine creating the ARP reply (Network order)
 * @param target_ip IP of the machine that previously asked for sender's
 * MAC address (Network order)
 * @param interface Interface of the sender machine to send the reply message
 */
void send_arp_reply(uint8_t *sender_mac, uint8_t *target_mac,
                    uint32_t sender_ip, uint32_t target_ip,
                    int interface);


/**
 * Dynamically allocates memory for a copy of the orig_packet (because it will
 * disappear when a new packet will be received) and creates a new arp_queue_entry,
 * then enqueues it in the router's packet_queue.
 *
 * Note that the additional packet must be freed after dequeue and send.
 *
 * @param packet_queue Queue of packets, owned by the router.
 * @param orig_packet Packet to be added to the queue.
 * @param packet_len Size of the original packet.
 */
void add_packet_in_queue(arp_packet_queue *packet_queue, char *orig_packet,
                         struct route_table_entry *best_route, size_t packet_len);


/**
 * Searches the ARP cache for target_ip.
 * @param arp_cache List of already discovered IP-MAC mappings
 * @param target_ip IP of the next hop machine (host order)
 * @return The MAC address of the next hop machine, if found, NULL, otherwise.
 */
uint8_t *search_addr_in_cache(list arp_cache, uint32_t target_ip);



int check_for_broadcast(uint8_t *target_mac);


/**
 * Allocates memory for an ARP packet (Ethernet header + ARP header).
 * Can be used for both ARP request and ARP reply, if given the correct params.
 * Memory must be freed after sending the packet.
 * @param sender_mac Sender MAC - for both Eth and ARP
 * @param target_mac Target MAC - for both Eth and ARP, might be
 * ff:ff:ff:ff:ff:ff (when broadcasting)
 * @param sender_ip Sender IP (Network order)
 * @param target_ip Target IP (Network order)
 * @param arp_op ARP opcode (1 for request, 2 for reply)
 * @return ARP packet
 */
char *create_arp_packet(uint8_t *sender_mac, uint8_t *target_mac,
                        uint32_t sender_ip, uint32_t target_ip,
                        uint16_t arp_op);


/**
 * Updates the ARP cache with the newly received entry and iterates the packet
 * queue, sending all the packets whose next hop's MAC has been discovered
 * @param arp_hdr ARP header of the newly ARP reply
 */
void handle_arp_reply(struct arp_header *arp_hdr, list *arp_cache,
                      arp_packet_queue *packet_queue);



/**
 * Allocates memory for a new cache entry and adds it in the arp_cache.
 * @param arp_cache Pointer to the router cache, containing already
 * discovered ARP mappings
 * @param ip New IPv4 address (Network order)
 * @param mac New MAC address
 */
void add_cache_entry(list *arp_cache, uint32_t ip, uint8_t *mac);


/**
 * Tries to send the packet with best_route already known, by first searching
 * the cache for the MAC of the destination IP. If found, the packet is sent,
 * else, an ARP request is sent and the packet is enqueued in the packet queue.
 * @param packet Packet to send
 * @param packet_len Length of the packet
 * @param best_route Route previously determined by the LPM algorithm
 */
void send_packet_safely(char *packet, size_t packet_len, list arp_cache,
                        arp_packet_queue *packet_queue,
                        struct route_table_entry *best_route);


#endif /* ARP_H */
