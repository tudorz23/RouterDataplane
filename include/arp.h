#ifndef ARP_H
#define ARP_H

#include "queue.h"
#include "list.h"
#include "lib.h"
#include "protocols.h"
#include "utils.h"

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2


struct arp_cache_entry {
    uint32_t ip;
    uint8_t mac[6];
};

typedef struct arp_cache_entry arp_cache_entry;


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
 * disappear when a new packet will be received) and enqueues it in the
 * router's packet_queue.
 *
 * Note that the additional packet must be freed after dequeue and send.
 *
 * @param packet_queue Queue of packets, owned by the router.
 * @param orig_packet Packet to be added to the queue.
 * @param packet_len Size of the original packet.
 */
void add_packet_in_queue(queue packet_queue, char *orig_packet, int packet_len);


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
                        uint16_t arp_op)

#endif /* ARP_H */
