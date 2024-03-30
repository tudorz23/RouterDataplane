#include "icmp.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "forwarding.h"


void generate_icmp_reply(struct iphdr *ip_hdr, size_t packet_len, list arp_cache,
                         arp_packet_queue *packet_queue, struct route_table_entry *route_table,
                         int rtable_size) {
    struct icmphdr *icmp_hdr = (struct icmphdr*) (((char*) ip_hdr) + sizeof(struct iphdr));

    // Create the answer packet.
    char *ans_packet = malloc(packet_len);
    DIE(!ans_packet, "ICMP reply malloc failed.");

    struct ether_header *ans_eth_header = (struct ether_header*) ans_packet;
    ans_eth_header->ether_type = htons(ETHER_TYPE_IPV4);

    // Complete IPv4 header.
    struct iphdr *ans_ip_hdr = (struct iphdr*) (ans_packet + sizeof(struct ether_header));
    ans_ip_hdr->ihl = 5;
    ans_ip_hdr->version = 4;
    ans_ip_hdr->tos = 0;
    ans_ip_hdr->tot_len = ip_hdr->tot_len;
    ans_ip_hdr->id = ip_hdr->id;
    ans_ip_hdr->frag_off = ip_hdr->frag_off;
    ans_ip_hdr->ttl = 64; // Default value
    ans_ip_hdr->protocol = IPV4_ICMP;
    ans_ip_hdr->check = 0; // Initial value
    ans_ip_hdr->saddr = ip_hdr->daddr;
    ans_ip_hdr->daddr = ip_hdr->saddr;

    // Complete ICMP header.
    struct icmphdr *ans_icmp_hdr = (struct icmphdr*) (ans_packet + sizeof(struct ether_header)
                                                      + sizeof(struct iphdr));
    ans_icmp_hdr->type = ICMP_ECHO_REPLY_TYPE;
    ans_icmp_hdr->code = 0;
    ans_icmp_hdr->checksum = 0; // Initial value
    ans_icmp_hdr->un.echo.id = icmp_hdr->un.echo.id;
    ans_icmp_hdr->un.echo.sequence = icmp_hdr->un.echo.sequence;

    // Copy the data from the original packet.
    char *data = (char *) (((char *) icmp_hdr) + sizeof(struct icmphdr));
    size_t data_len = packet_len - (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));

    char *ans_data = (char *) (((char *) ans_icmp_hdr) + sizeof(struct icmphdr));
    memcpy(ans_data, data, data_len);

    // Compute the checksums.
    ans_ip_hdr->check = htons(checksum((uint16_t *) ans_ip_hdr, sizeof(struct iphdr)));
    ans_icmp_hdr->checksum = htons(checksum((uint16_t *) ans_icmp_hdr,
                                            sizeof(struct icmphdr) + data_len));

    struct route_table_entry *best_route = get_best_route(route_table, rtable_size,
                                                          ntohl(ans_ip_hdr->daddr));
    DIE(!best_route, "There should be a valid route.");

    send_packet_safely(ans_packet, packet_len, arp_cache, packet_queue, best_route);
    free(ans_packet);
}
