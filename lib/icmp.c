#include "icmp.h"
#include <netinet/in.h>
#include <arpa/inet.h>


void create_icmp_reply(struct iphdr *ip_hdr, size_t packet_len, list arp_cache,
                       arp_packet_queue *packet_queue, route_table_t *route_table) {
    struct icmphdr *icmp_hdr = (struct icmphdr*) (((char*) ip_hdr) + sizeof(struct iphdr));

    // Create the answer packet.
    char *ans_packet = malloc(packet_len);
    DIE(!ans_packet, "ICMP reply malloc failed.\n");

    struct ether_header *ans_eth_hdr = (struct ether_header*) ans_packet;
    ans_eth_hdr->ether_type = htons(ETHER_TYPE_IPV4);

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

    struct route_table_entry *best_route = get_best_route(route_table,
                                            ntohl(ans_ip_hdr->daddr));
    DIE(!best_route, "There should be a valid route.\n");

    send_packet_safely(ans_packet, packet_len, arp_cache, packet_queue, best_route);
    free(ans_packet);
}


void create_icmp_error(struct iphdr *ip_hdr, uint8_t error_type, list arp_cache,
                       arp_packet_queue *packet_queue, route_table_t *route_table) {
    // Total size of the packet, consisting of the headers and first
    // 64 bits (i.e. 8 bytes) of data from the original packet.
    size_t err_packet_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr)
                            + sizeof(struct iphdr) + 8;

    // Create the error packet.
    char *err_packet = malloc(err_packet_len);
    DIE(!err_packet, "ICMP error malloc failed.\n");

    struct ether_header *err_eth_hdr = (struct ether_header*) err_packet;
    err_eth_hdr->ether_type = htons(ETHER_TYPE_IPV4);

    // Complete IPv4 header.
    struct iphdr *err_ip_hdr = (struct iphdr*) (err_packet + sizeof(struct ether_header));
    err_ip_hdr->ihl = 5;
    err_ip_hdr->version = 4;
    err_ip_hdr->tos = 0;
    err_ip_hdr->tot_len = htons(err_packet_len - sizeof(struct ether_header));
    err_ip_hdr->id = htons(1);
    err_ip_hdr->frag_off = htons(0);
    err_ip_hdr->ttl = 64; // Default value
    err_ip_hdr->protocol = IPV4_ICMP;
    err_ip_hdr->check = 0; // Initial value
    err_ip_hdr->daddr = ip_hdr->saddr;

    // Best route is needed to deduce the source IP and MAC.
    struct route_table_entry *best_route = get_best_route(route_table,
                                    ntohl(err_ip_hdr->daddr));
    DIE(!best_route, "There should be a valid route.\n");

    uint32_t source_ip = inet_addr((get_interface_ip(best_route->interface)));
    uint8_t source_mac[6];
    get_interface_mac(best_route->interface, source_mac);

    err_ip_hdr->saddr = source_ip;

    // Complete ICMP header.
    struct icmphdr *err_icmp_hdr = (struct icmphdr*) (err_packet + sizeof(struct ether_header)
                                                      + sizeof(struct iphdr));
    err_icmp_hdr->type = error_type;
    err_icmp_hdr->code = 0;
    err_icmp_hdr->checksum = 0; // Initial value

    // Copy the IPv4 header and 8 bytes of data after it from the original packet.
    char *ip_hdr_copy = (char*)(((char*) err_icmp_hdr) + sizeof(struct icmphdr));
    memcpy(ip_hdr_copy, ip_hdr, sizeof(struct iphdr) + 8);

    // Compute the checksums.
    err_ip_hdr->check = htons(checksum((uint16_t *) err_ip_hdr, sizeof(struct iphdr)));
    err_icmp_hdr->checksum = htons(checksum((uint16_t *) err_icmp_hdr,
                                            sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

    send_packet_safely(err_packet, err_packet_len, arp_cache, packet_queue, best_route);
    free(err_packet);
}
