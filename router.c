#include "queue.h"
#include "lib.h"
#include "forwarding.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "arp.h"

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    // Route table is in network order.
    struct route_table_entry *route_table = malloc(MAX_RTABLE_LEN * sizeof(struct route_table_entry));
    DIE(!route_table, "Route table malloc failed.");

    int rtable_size = read_rtable(argv[1], route_table);

    qsort((void *) route_table, rtable_size, sizeof(struct route_table_entry),
            rtable_compare_func);

    // Initialize the ARP cache and the packet queue.
    list arp_cache = NULL;
    arp_packet_queue *packet_queue = init_packet_queue();

    while (1) {
        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *eth_hdr = (struct ether_header*) buf;

        // IP of the current interface.
        char *dot_local_ip = get_interface_ip(interface); // IP in dot form
        uint32_t local_ip = inet_addr(dot_local_ip); // IP in network order

        // MAC of the current interface.
        uint8_t local_recv_mac[6];
        get_interface_mac(interface, local_recv_mac);

        if (!check_destination_validity(eth_hdr->ether_dhost, local_recv_mac)) {
            continue;
        }

        printf("Ether type is %x\n", ntohs(eth_hdr->ether_type));

        if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_IPV4) {
            struct iphdr *ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));

            // Check if the router is the actual destination.
            if (ip_hdr->daddr == local_ip) {
                if (ip_hdr->protocol == IPV4_ICMP) {
                    // TODO: Handle ICMP request.
                    printf("Got an ICMP req.\n");
                    continue;
                }
            }

            if (!authorize_checksum(ip_hdr)) {
                // Wrong checksum.
                continue;
            }

            if (!update_ttl(ip_hdr)) {
                // TODO: Send back an ICMP message with "Time exceeded".
                continue;
            }

            struct route_table_entry *best_route = get_best_route(route_table, rtable_size,
                                                                ntohl(ip_hdr->daddr));
            if (!best_route) {
                // TODO: ICMP with "Destination unreachable".
                printf("Destination unreachable.\n");
                continue;
            }

            send_packet_safely(buf, len, local_ip, packet_queue, arp_cache, best_route);

        } else if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP) {
            struct arp_header *arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));

            if (ntohs(arp_hdr->op) == ARP_OP_REQUEST) {
                if (arp_hdr->tpa == local_ip) {
                    send_arp_reply(local_recv_mac, arp_hdr->sha, local_ip,
                                   arp_hdr->spa, interface);
                    continue;
                }
            } else {
                // Received an ARP_OP_REPLY
                handle_arp_reply(arp_hdr, &arp_cache, packet_queue);
            }
        }
    }
}

