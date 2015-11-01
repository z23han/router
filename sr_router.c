/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);


    /* copy into a new packet for better handling :) */
    uint8_t *packet1 = packet;

    printf("*** -> Received packet of length %d \n",len);

    /* sanity-check the packet (meets min length) */
    if (!check_min_length(len, ETHER_PACKET_LEN)) {
        fprintf(stderr, "packet length is smaller the ethernet size. Drop it!\n");
        return;
    }

    uint16_t eth_type = ethertype(packet1);

    /* ARP REQUEST & REPLY */
	
    if (eth_type == ethertype_arp) {
        fprintf(stderr, "********** ARP packet **********\n");
        sr_handle_arppacket(sr, packet1, len, interface);
        return;
    }
    /* IP REQUEST & REPLY */
    else if (eth_type == ethertype_ip) {
        fprintf(stderr, "********** IP packet **********\n");
        sr_handle_ippacket(sr, packet1, len, interface);
        return;
    }
    /* OTHERWISE, DROP!!! */
    else {
        fprintf(stderr, "Invalid ethernet type, drop the packet!\n");
        return;
    }

    return;

}/* end sr_ForwardPacket */


/* handle/generate ARP packet */
void sr_handle_arppacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) 
{
    assert(sr);
    assert(packet);
    assert(interface);

    /* Get ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)get_eth_hdr(packet);

    /* Get arp header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)get_arp_hdr(packet);

    /* Check the arp packet minimum length */
    if (!check_min_length(len, ARP_PACKET_LEN)) {
        fprintf(stderr, "arp packet length is not enough:(\n");
        return;
    }

    /* check the opcode to see if it is request or reply */
    unsigned short ar_op = ntohs(arp_hdr->ar_op);
    /* Get the interface and see if it matches the router */
    struct sr_if *sr_iface = sr_get_interface(sr, interface);
    if (sr_iface) {
        /* ********** ARP request ********** */
        /* Construct an arp reply and send it back */
        if (ar_op == arp_op_request) {
            fprintf(stderr, "********** ARP REQUEST **********\n"); /* ar_op = 1 */
            /* Set the back-packet length */
            int packet_len = ARP_PACKET_LEN;
            uint8_t *arp_reply_hdr = (uint8_t *)malloc(packet_len);

            /* Create ethernet header */
            create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)arp_reply_hdr, sr_iface);

            /* Create arp header */
            create_back_arp_hdr(arp_hdr, (sr_arp_hdr_t *)((unsigned char *)arp_reply_hdr+ETHER_PACKET_LEN), sr_iface);

            /* Send APR reply */
            sr_send_packet(sr, (sr_ethernet_hdr_t *)arp_reply_hdr, packet_len, sr_iface->name);
            fprintf(stderr, "********** Sent ARP reply packet successfully!!\n");
            free(arp_reply_hdr);
            return;
        }
        /* ********** ARP reply ********** */
        /* Cache it, go thru my request queue and send outstanding packets */
        else if (ar_op == arp_op_reply) {
            fprintf(stderr, "********** ARP REPLY **********\n");  /* ar_op = 2 */
            /* cache first, and send all the packets in the queue with ip->mac mapping!!! */
            handle_arpreply(arp_hdr, sr);
            return;
        }
        /* ********** Otherwise, error! ********** */
        else {
            fprintf(stderr, "Invalid arp type!!!\n");
            return;
        }
    } else {
        fprintf(stderr, "Router doesnt have this interface, drop it!\n");
        return;
    }
    
    return;
}


/* Handle IP packet */
void sr_handle_ippacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */) 
{
    assert(sr);
    assert(packet);
    assert(interface);

    /* Get ethernet header */
    sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);

    /* Get ip header */
    sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);

    /* Get the arp cache */
    struct sr_arpcache *sr_arp_cache = &sr->cache;

    /* Get the interface on the router */
    struct sr_if *sr_iface = sr_get_interface(sr, interface);

    /* Get the protocol from IP */
    uint8_t ip_p = ntohs(ip_hdr->ip_p);

    /* If the packet is sent to self, meaning the ip is sent to the router */
    if (sr_iface->ip == ip_hdr->ip_dst) {
        /* Check the protocol if it is icmp */
        if (ip_p == ip_protocol_icmp) {
            /* Get the icmp header */
            sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);

            /* Check if it is ICMP echo request */
            /* icmp_echo_req = 8 */
            if (ntohs(icmp_hdr->icmp_type) == 8) {
                int packet_len = ICMP_PACKET_LEN;
                uint8_t *icmp_reply_hdr = (uint8_t *)malloc(packet_len);

                /* Create ethernet header */
                create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)icmp_reply_hdr, sr_iface);

                /* Create ip header */
                create_echo_ip_hdr(ip_hdr, (sr_ip_hdr_t *)((char *)icmp_reply_hdr+ETHER_PACKET_LEN));

                /* Create icmp header */
                create_icmp_hdr(icmp_hdr, (sr_icmp_hdr_t *)((char *)icmp_reply_hdr+IP_PACKET_LEN));

                /* Send icmp echo reply */
                sr_send_packet(sr, icmp_reply_hdr, packet_len, sr_iface->name);
                fprintf(stderr, "********** Sent ICMP reply packet successfully!!\n");
                free(icmp_reply_hdr);
                return;
            } else {
                fprintf(stderr, "Not an ICMP request!\n");
                return;
            }
        }
        /* Else it is TCP/UDP request */
        else {
            fprintf(stderr, "*** -> Received TCP/UDP!\n");
            /* Send ICMP port unreachable */
            int packet_len = ICMP_T3_PACKET_LEN;
            uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);

            /* Create ethernet header */
            create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)icmp_t3_hdr, sr_iface);

            /* Create ip header */
            create_echo_ip_hdr(ip_hdr, (sr_ip_hdr_t *)((char *)icmp_t3_hdr+ETHER_PACKET_LEN));

            /* Send icmp type 3 port unreachable */
            /* Create icmp port unreachable packet */
            /* icmp_t3 type=3, code=3 */
            create_icmp_t3_hdr(ip_hdr, (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr+IP_PACKET_LEN), 3, 3);

            /* Send icmp type 3 packet */
            sr_send_packet(sr, icmp_t3_hdr, packet_len, sr_iface->name);

            free(icmp_t3_hdr);
            return;
        }
    }
    /* Else Check the routing table, perfomr LPM */
    else {
        /* Sanity-check the packet */
        /* minimum length */
        if (!check_min_length(len, IP_PACKET_LEN)) {
            fprintf(stderr, "The packet length is not enough:(\n");
            return;
        }
        /* checksum */
		/* Set the checksum to be 0 after recording the checksum */
		uint16_t old_ip_sum = ip_hdr->ip_sum;
		ip_hdr->ip_sum = 0;
        if (!verify_checksum(ip_hdr, sizeof(sr_ip_hdr_t), old_ip_sum)) {
            fprintf(stderr, "CHECKSUM FAILED!!\n");
            return;
        }
        /* decrement the ttl by 1 */
        ip_hdr->ip_ttl--;
        /* recompute the packet checksum over the modified header */
        ip_hdr->ip_sum = 0;
		uint16_t new_ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
		ip_hdr->ip_sum = new_ip_sum;
        /* Do LPM on the routing table */
        /* Check the routing table and see if the incoming ip matches the routing table ip, and find LPM router entry */
        struct sr_rt *dst_lpm = sr_lpm(sr, ip_hdr->ip_dst);
        if (dst_lpm) {
            /* check ARP cache */
            struct sr_if *out_if = sr_get_interface(sr, dst_lpm->interface);
            struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr_arp_cache, dst_lpm->gw.s_addr);
            /* If hit, meaning the arp_entry is found */
            if (arp_entry) {
                /* Send frame to next hop */
                fprintf(stderr, "There is a match in the ARP cache!!\n");
                /* update the eth_hdr source and destination ethernet address */
                /* use next_hop_ip->mac mapping in the entry to send the packet */
                memcpy(eth_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
                sr_send_packet(sr, packet, len, out_if->name);
                /* free the entry */
                free(arp_entry);
                return;
            } else/* No Hit */ {
                /* send an ARP request for the next-hop IP */
                /* add the packet to the queue of packets waiting on this ARP request */
                fprintf(stderr, "No match in the ARP cache:(\n");
                /* Add request to ARP queue*/
                struct sr_arpreq *arp_req = sr_arpcache_queuereq(sr_arp_cache, ip_hdr->ip_dst, packet, len, out_if->name);
                /* send ARP request, this is a broadcast */
                handle_arpreq(arp_req, sr);
                return;
            }
        } else /* if not matched */ {
            /* Send ICMP net unreachable */
            int packet_len = ICMP_T3_PACKET_LEN;
            uint8_t *icmp_t3_hdr = (uint8_t *)malloc(packet_len);

            /* Create ethernet header */
            create_ethernet_hdr(eth_hdr, (sr_ethernet_hdr_t *)icmp_t3_hdr, sr_iface);

            /* Create ip header */
            create_echo_ip_hdr(ip_hdr, (sr_ip_hdr_t *)((char *)icmp_t3_hdr+ETHER_PACKET_LEN));

            /* Create icmp net unreachable */
            /* icmp_t3 type=3, code=0 */
            create_icmp_t3_hdr(ip_hdr, (sr_icmp_t3_hdr_t *)((char *)icmp_t3_hdr+IP_PACKET_LEN), 3, 0);

            /* Send icmp type 3 packet */
            sr_send_packet(sr, icmp_t3_hdr, packet_len, sr_iface->name);

            free(icmp_t3_hdr);
            return;
        }
    }

    return;
}


/* Get the ethernet header */
sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet) {
    assert(packet);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
    if (!eth_hdr) {
        fprintf(stderr, "Failed to get the ethernet header!\n");
        return 0;
    } 
    return eth_hdr;
}


/* Get the arp header */
sr_arp_hdr_t * get_arp_hdr(uint8_t *packet) {
    assert(packet);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((unsigned char *)packet + ETHER_PACKET_LEN);
    if (!arp_hdr) {
        fprintf(stderr, "Failed to get arp header!\n");
        return 0;
    } 
    return arp_hdr;
}


/* Get IP header */
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet) {
    assert(packet);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)((unsigned char *)packet + ETHER_PACKET_LEN);
    if (!ip_hdr) {
        fprintf(stderr, "Failed to get ip header!\n");
        return 0;
    }
    return ip_hdr;
}


/* Get icmp header */
sr_icmp_hdr_t *get_icmp_hdr(uint8_t *packet) {
    assert(packet);
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)((unsigned char *)packet + IP_PACKET_LEN);
    if (!icmp_hdr) {
        fprintf(stderr, "Failed to get icmp header!\n");
        return 0;
    }
    return icmp_hdr;
}


/* Create ethernet header */
void create_ethernet_hdr(sr_ethernet_hdr_t *eth_hdr, sr_ethernet_hdr_t *new_eth_hdr, struct sr_if *sr_iface) {
    assert(eth_hdr);
    assert(new_eth_hdr);
    /* swap the sender and receiver ethernet addresses */
    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, sr_iface->addr, ETHER_ADDR_LEN);
    /* type should be the same as the input ethernet */
    new_eth_hdr->ether_type = eth_hdr->ether_type;
    return;
}


/* Create arp header reply back */
void create_back_arp_hdr(sr_arp_hdr_t *arp_hdr, sr_arp_hdr_t *new_arp_hdr, struct sr_if *sr_iface) {
    assert(arp_hdr);
    assert(new_arp_hdr);
    /* these terms should be the same as input arp */
    new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    new_arp_hdr->ar_pro = arp_hdr->ar_pro;
    new_arp_hdr->ar_hln = arp_hdr->ar_hln;
    new_arp_hdr->ar_pln = arp_hdr->ar_pln;
    /* here we form the arp opcode as reply */
    new_arp_hdr->ar_op = htons(arp_op_reply);
    /* target ip address is the sender ip */
    new_arp_hdr->ar_tip = arp_hdr->ar_sip;
    /* sender ip address is the router ip */
    new_arp_hdr->ar_sip = sr_iface->ip;
    /* target mac address is the sender mac address */
    memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    /* sender mac address is the router mac address */
    memcpy(new_arp_hdr->ar_sha, sr_iface->addr, ETHER_ADDR_LEN);
    return;
}


/* Create echo ip header */
void create_echo_ip_hdr(sr_ip_hdr_t *ip_hdr, sr_ip_hdr_t *new_ip_hdr) {
    assert(ip_hdr);
    assert(new_ip_hdr);
    new_ip_hdr->ip_tos = ip_hdr->ip_tos;        /* type of service */
    new_ip_hdr->ip_len = ip_hdr->ip_len;        /* total length */
    new_ip_hdr->ip_id = ip_hdr->ip_id;          /* identification */
    new_ip_hdr->ip_off = ip_hdr->ip_off;        /* fragment offset field */
    new_ip_hdr->ip_ttl = 64;                    /* time to live */
    new_ip_hdr->ip_p = ip_hdr->ip_p;            /* protocol */
    /* do we need to check the checksum??? */
    new_ip_hdr->ip_sum = ip_hdr->ip_sum;        /* checksum */
    /* source and destination should be altered */
    new_ip_hdr->ip_src = ip_hdr->ip_dst;        /* source address */
    new_ip_hdr->ip_dst = ip_hdr->ip_src;        /* dest address */
    return;
}


/* Create icmp header */
void create_icmp_hdr(sr_icmp_hdr_t *icmp_hdr, sr_icmp_hdr_t *new_icmp_hdr) {
    assert(icmp_hdr);
    assert(new_icmp_hdr);
    /* here we construct a echo reply icmp */
    new_icmp_hdr->icmp_type = htons(0);
    /* code and checksum should be the same */
    new_icmp_hdr->icmp_code = icmp_hdr->icmp_code;
    /* do we need to check the checksum??? */
    new_icmp_hdr->icmp_sum = icmp_hdr->icmp_sum;
    return;
}


/* Create type3 icmp header */
void create_icmp_t3_hdr(sr_ip_hdr_t *ip_hdr, sr_icmp_t3_hdr_t *icmp_t3_hdr, uint8_t icmp_type, uint8_t icmp_code) {
    assert(icmp_t3_hdr);
    /* type here should be 3 actually */
    icmp_t3_hdr->icmp_type = htons(icmp_type);
    /* get the icmp code from the input */
    icmp_t3_hdr->icmp_code = htons(icmp_code);
    uint16_t checksum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
    icmp_t3_hdr->icmp_sum = htons(checksum);
    icmp_t3_hdr->unused = htons(0);
    icmp_t3_hdr->next_mtu = htons(1500);
    memcpy(icmp_t3_hdr->data, ip_hdr, ICMP_DATA_SIZE);
    return;
}


/* Check the checksum */
int verify_checksum(void *_data, int len, uint16_t packet_cksum) {
    if (cksum(_data, len) == packet_cksum) {
        return 1;
    } else {
        fprintf(stderr, "checksum is not correct!\n");
        return 0;
    }
}


/* Check the min length of input packet */
int check_min_length(unsigned int len, unsigned int packet_len) {
    if (len < packet_len) {
        fprintf(stderr, "packet length doesn't satisfy the minimum length requirements!\n");
        return 0;
    } else {
        return 1;
    }
}


/* Find the longest prefix match */
struct sr_rt *sr_lpm(struct sr_instance *sr, uint32_t ip_dst) {
    /* sr_rt is a linkedList until reaching the end */
    struct sr_rt *routing_table = sr->routing_table;
    int len = 0;
    struct sr_rt *lpm_rt = sr->routing_table;
    while (routing_table) {
        if ((ip_dst & routing_table->mask.s_addr) == (routing_table->dest.s_addr & routing_table->mask.s_addr)) {
            if (len < routing_table->mask.s_addr) {
                len = routing_table->mask.s_addr;
                lpm_rt = routing_table;
            }
        }
        routing_table = routing_table->next;
    }
    return lpm_rt;
}


/* Send arp request packet, this is broadcast */
void send_arp_req_packet(struct sr_instance *sr, char * out_iface, uint32_t dest_ip) {
    assert(sr);
    assert(out_iface);
    assert(dest_ip);
    /* Get the interface from the router */
    struct sr_if *out_if = sr_get_interface(sr, out_iface);

    int packet_len = ARP_PACKET_LEN;
    uint8_t *arp_req_hdr = (uint8_t *)malloc(packet_len);
    /* Create ethernet header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arp_req_hdr;
    memcpy(eth_hdr->ether_dhost, out_if->addr, ETHER_ADDR_LEN);     /* destination ethernet address */
	int i;
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {                      /* source ethernet address */
        eth_hdr->ether_shost[i] = htons(255);          
    }
    eth_hdr->ether_type = htons(ethertype_arp);             /* packet type ID */

    /* Create arp header */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)((char *)arp_req_hdr + ETHER_PACKET_LEN);
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);      /* format of hardware address   */
    arp_hdr->ar_pro = htons(ethertype_arp);         /* format of protocol address   */
    arp_hdr->ar_hln = ETHER_ADDR_LEN;               /* length of hardware address   */
    arp_hdr->ar_pln = htons(4);                     /* length of protocol address   */
    arp_hdr->ar_op = htons(arp_op_request);         /* ARP opcode (command)         */
    /* sender hardware address      */
    memcpy(arp_hdr->ar_sha, out_if->addr, ETHER_ADDR_LEN);
    /* sender IP address            */
    arp_hdr->ar_sip = out_if->ip;
    /* target hardware address      */
    for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        arp_hdr->ar_tha[i] = htons(255);
    }
    /* target IP address            */
    arp_hdr->ar_tip = dest_ip;
    
    /* Send arp request packet */
    sr_send_packet(sr, arp_req_hdr, packet_len, out_if->name);
    free(arp_req_hdr);
    return;
}
