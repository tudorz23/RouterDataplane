*Designed by Marius-Tudor Zaharia, 323CA, March 2024*

# RouterDataplane

---

## Table of contents
1. [What is RouterDataplane?](#what-is-routerdataplane)
2. [File distribution](#file-distribution)
3. [Network simulation and running](#network-simulation-and-running)
4. [Implementation details](#implementation-details)
    * [General flow](#general-flow)
    * [IPv4](#ipv4)
      * [Forwarding](#forwarding)
      * [LPM using Trie](#lpm-using-trie)
      * [ICMP](#icmp)
    * [ARP](#arp)
      * [ARP request](#arp-request)
      * [ARP reply](#arp-reply)
      * [General details](#general-details)

---

## What is RouterDataplane?
* RouterDataplane is a basic implementation of the forwarding plane of a
network router in the C language (the routing algorithms part is considered to
have been already done).
* The project contains solutions to IPv4 packet forwarding, including ARP
requests and replies and also ICMP Echo and error messages.

---

## File distribution
* For an easier development and readability, the project is structured in
several files, as follows:
  * The main router logic is in `router.c`;
  * The general IPv4 forwarding logic is in `forwarding.c / .h`;
  * The ARP implementation is in `arp.c / .h`;
  * The ICMP logic is in `icmp.c / .h`;
  * The basic trie implementation can be found in `trie.c / .h`;
  * There is also a file `utils.c` with general utility functions.

---

## Network simulation and running
* To simulate the network topology using `Mininet`, the command
`sudo python3 checker/topo.py` should be run, followed by `make run_router#i`
from the terminal of the router number `#i`.
* To run the pre-defined tests, run `./checker/checker.sh`.

---

## Implementation details
### General flow
* The router receives packets from the network.
* If the destination MAC address does not match the router's MAC from the
receiving interface and neither is it the broadcast MAC (`ff:ff:ff:ff:ff:ff`),
it drops the packet.
* It then checks the `Ethernet` header to find out the type of the packet,
only taking into account `IPv4` and `ARP` packets.
* If it received any other packet type, it discards it.

---

### IPv4
* If the received packet is of IPv4 type, the router must either forward it
(if the router itself is not the final destination) or send an ICMP message in
various situations.

#### Forwarding
* If the packet has a wrong checksum, the router drops it.
* If the TTL is less than or equal to one, it also drops it, after sending an
ICMP error message.
* If the packet passed the previous requirements, the router applies the LPM
(Longest Prefix Match) algorithm, which returns the best route from the routing
table for forwarding the packet to the destination.
* If no route is found, an ICMP error message is sent.
* If there is a route, the router must determine the MAC address of the next
hop, either by taking it from a cache or by using ARP, and then sends it.

#### LPM using Trie
* To determine the best route for a packet from the routing table, the basic
method would be to linearly traverse it, which proves inefficient for a big
table.
* The preferred solution is the usage of the `trie` data structure (a more
specific implementation of it).
* The main idea is that each IPv4 prefix can be written in binary as a sequence
of `1's` and `0's`. The trie will store, for an IPv4 prefix, a path as long as
the length of the `1` bit sequence of the mask. For example, for a /16 mask,
it will store a path for the first 16 bits of the prefix.
* Each node of the trie has at most two children, with the following meaning:
if the next bit of the prefix is a `0`, the path of the `left` child should be
taken, and if it is a `1`, the path of the `right` child is the good one.
* The `trie` structure also has a `final_state` attribute, which, when set to
`TRUE`, marks that the given node is at the end of a prefix (thus allowing the
storage of prefixes that start with a common bit sequence on the same trie
path), so it is possible to store longer and shorter prefixes.
* The `entry` attribute points to an entry of the `route table` for the nodes
that have the `final_state` on `TRUE`.
* Thus, the insertion of the prefixes in the trie is done in O(n), by
traversing the route table once, but the search for an IP address - prefix
match can now be done in O(1), by traversing at most 32 nodes of the trie
(32 is the length of an IP address), much better than linear searching (O(n))
or binary search (O(log n)).

#### ICMP
* i.e `Internet Control Message Protocol`.
* If the IPv4 packet is destined to the router itself and is of type `ICMP Echo
request`, the router responds with an `ICMP Echo reply` message packet. The
packet is completed in accordance with the ICMP standard, by completing the
Ethernet, IPv4 and ICMP headers and by copying the additional data present in
the original packet as payload.
* If the received packet has an invalid TTL or if no route can be found with
the LPM algorithm, an `ICMP Time exceeded` or `ICMP Destination unreachable`
packet is sent back to the original sender. The packet is filled by completing
the Ethernet, IPv4 and ICMP headers, but also by copying the IPv4 header of the
original packet and the first 64 bits (i.e. 8 bytes) that follow it.

---

### ARP
* i.e. `Address Resolution Protocol`.
* It is used for deducing the MAC address of the next hop with an IP found by
the LPM algorithm.
* The router uses a cache to store already found `IP-MAC` mappings. In this
implementation, the cache is a list, preferred instead of an array because the
number of entries should be low, and a list will have as many nodes as there 
are cache entries, while an array with a pre-set length will use more memory
than it needs.

#### ARP request
* If the router does not find the needed IP-MAC mapping in the cache, it saves
the packet for later by enqueuing it in a `packet_queue`, to be able to handle
other packets while waiting for the needed MAC.
* It then generates an ARP request, using the `broadcast` MAC address, asking
for the MAC of the machine with the given IP.

#### ARP reply
* When the router receives an ARP reply packet, it adds the newly discovered
IP-MAC mapping to the cache and traverses the queue, searching for packets
whose target MAC address is now known.
* Note that the router can also be queried for his own MAC address, in which
case it should send an ARP reply itself.

#### General details
* The used structure for the queue is the custom `arp_packet_queue`, which also
stores the queue size necessary for the traversal. The entries contain pointers
to the packet allocated memory and to the previously determined best route, so
it is not necessary to run LPM again.
* The function `create_arp_packet()` is a really nice way to modularize the
code, as it is used by both `send_arp_request()` and `send_arp_reply()`.
* `send_packet_safely()` encapsulates all the `send` steps, by using ARP, and
should always be used after performing the LPM.
