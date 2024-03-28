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


    // TODO: Delete and replace with dynamic ARP.
    // Network order.
    struct arp_table_entry *arp_table = malloc(50 * sizeof (struct arp_table_entry));
    DIE(!arp_table, "ARP table malloc failed.");
    int arp_table_size = parse_arp_table("arp_table.txt", arp_table);

    // Initialize the ARP cache and the packet queue.
    list arp_cache = NULL;
    queue packet_queue = queue_create();

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header*) buf;

        // IP and MAC of the current interface.
        char *local_ip = get_interface_ip(interface); // IP in dot form
        uint8_t local_mac[6];
        get_interface_mac(interface, local_mac);

        if (!check_destination_validity(eth_hdr->ether_dhost, local_mac)) {
            continue;
        }

        printf("Ether type is %x\n", ntohs(eth_hdr->ether_type));

        if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_IPV4) {
            struct iphdr *ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));

            if (ip_hdr->daddr == inet_addr(local_ip)) {
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

            struct route_table_entry *best_route = get_best_route(route_table,
                                                rtable_size, ntohl(ip_hdr->daddr));
            if (!best_route) {
                // TODO: ICMP with "Destination unreachable".
                printf("Destination unreachable.\n");
                continue;
            }

            // TODO: ARP request for the MAC of the target.
            uint32_t next_hop_ip = ntohl(best_route->next_hop);
            int send_interface = best_route->interface;

            uint8_t *next_hop_mac = get_next_hop_mac(arp_table, arp_table_size, next_hop_ip);
            get_interface_mac(send_interface, local_mac);

            update_mac_addresses(eth_hdr, next_hop_mac, local_mac);
            send_to_link(send_interface, buf, len);

        } else if (ntohs(eth_hdr->ether_type) == ETHER_TYPE_ARP) {
            // TODO: Either respond to a broadcast, or parse a reply to own broadcast.
            struct arp_header *arp_hdr = (struct arp_header*) (buf + sizeof(struct ether_header));

            if (check_for_broadcast(eth_hdr->ether_dhost)) {
                if (arp_hdr->tpa == inet_addr(local_ip)) {
                    // TODO: ARP reply with my MAC.
                    continue;
                }
            }
        }

	}
}

