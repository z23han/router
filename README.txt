/ ################# code structure overview and design logic flow ###################/

On the higher level, there are 3 functions associated with this assignment. One is sr_handlepacket, which we are given to implement and continue as the starting code. The other two are dealing with arp packet and ip packet, which are callded sr_handle_arppacket and sr_handle_ippacket. 

/ ********************* general packet ********************* /
Inside sr_handlepacket, we justify whether it is an arp packet or ip packet by checking ethernet type. If it is ethertype_arp, then we are guided to arp packet logic; if it is ethertype_ip, we are forwarded to ip packet logic; otherwise it should be dropped since these are the only 2 packet format we need to care about. 

My implementation on arp packet and ip packet follows the flow chart provided in the tutorial. Even though they are written separately in 2 functions, the logic are correlated by arp request and arp reply. These 2 functions are implemented in the sr_arpcache file. 

/ ********************* arp packet *********************
For the arp packet handling, we need to first justify whether it is an arp request or arp reply by checking arp opcode. If it is an arp request (arp_op_request), we simply create ethernet header and arp header, and then send the newly created packet back to the sender. However if it is an arp reply (arp_op_reply), we should cache the arp since we have found the ip->mac mapping, and send all the corresponding packets from our queue out to the destination. This is implemented in the handle_arpreply function in the sr_arpcache file. 

In general, throughout my code, I use the basic format of packet creation, which are packed into separate functions, such as create_ethernet_hdr, create_back_arp_hdr or create_echo_ip_hdr and create_icmp_t3_hdr (the latter 2 are used in the ip handling). This is convenient and straightforward for both code reading and writing. 

/ ********************* ip packet ********************* /
For ip packet handling, The first checking related to logic flow is whether it is sent to me (router), or other ip addresses. Of course, we should have checks like minimum length checking, ethernet and ip header checking beforehand, they are all combined in the similar format as arp packet handling initial checks. The sent-to checks is evaluated by finding the destination ip, and see if it matches any of my interface (the function is implemented in sr_get_router_if). 

/ ++++++++++++++++++++++++++ sent-to-me ++++++++++++++++++++++++++ /
If it is sent to me, I check the protocol, and see if it is an icmp request (ip_protocol_icmp). 

If it is an icmp request, we also need to make sure if it is in our cache. If it is in the cache, we construct an icmp echo reply by creating ethernet header, ip header and icmp header; however if not, we need to broadcast to all the ips and figure out the ip->mac mapping. 

But if it not an icmp request, we assume here that it could be tcp/udp. In this case, what we are doing follows the same process as above (arp cache checking or broadcast to find the ip->mac mapping), but send back the icmp port unreachable (type 3, code 3). icmp type 3 creation is formulated in a function called create_icmp_t3_hdr. 

/ ++++++++++++++++++++++++++ No sent-to-me ++++++++++++++++++++++++++ /
There are several cases if the packet is not sent to me. It can be a valid packet, which we are forwarding to the next hop. It can be an invalid packet, either not found the routing table (not fit the longest prefix match), or not found in the topology (passes the longest prefix match but cannot receive arp reply from arp broadcast). 

Thus we first check if it fits the longest prefix match, if it doesn't fit, we need to reply an icmp net unreachable (type 3, code 0). While if it fits, we check whether it is in our cache. If it's not there, we need to send broadcast to all the ips and find it out. In the arp broadcast, we send it 5 times. If we couldn't obtain any arp reply, we think it is an invalid ip address. Thus we should send icmp host unreachable (type 3, code 1). But if we obtain the arp reply from any ip, we get the ip address and can comfortably forward the packet to the target ip address. 



/ ################# Important functions ################# /
sr_handlepacket: obtain the packet and forward to arp handling or ip handing. 
sr_handle_arppacket: arp packet handling, forward to arp request handling or arp reply handling. 
sr_handle_ippacket: ip packet handling, including sent-to-me handling and sent-to-other handling. 
get_eth_hdr: get the ethernet header pointer. 
get_arp_hdr: get the arp header pointer. 
get_ip_hdr: get the ip header pointer. 
get_icmp_hdr: get the icmp header pointer. 
create_ethernet_hdr: create the ethernet header pointer. 
create_back_arp_hdr: create the arp header pointer. 
create_echo_ip_hdr: create the ip header pointer. 
create_icmp_hdr: create the icmp header pointer. 
create_icmp_t3_hdr: create the icmp type 3 header pointer. 
check_min_length: check the minimum length requirement. 
verify_checksum: check the checksum requirement. 
sr_lpm: get the longest prefix match routing entry. 
send_arp_req_packet_broadcast: send the arp broadcast to all the ips. 
sr_get_router_if: check if the router has such ip and return. 
handle_arpreq: handle arp request. 
handle_arpreply: handle arp reply. 
sr_arpcache_sweepreqs: get all the arp request from the cache and do the arp request handling. 


/ ################# Overcome difficulties !!! ################# /
We've encountered lots of problems during our code writing and debugging, and spent lots of hours fixing them. It's hard to list all of them, but I'm just picking some of the most annoying and concealing problems. 

- In the function sr_arpcache_sweepreqs, it's a must to store arp_req->next before handle_arpreq(), since arp_req would be destroyed if we haven't put the next pointer in our pocket. Besides, we initially wrote an if statement checking arp->next == NULL?, but this simply caused an infinite loop. And it took us a big amount of hours to figure out. 

- We didn't realize that we need to do the arp cache checking for all the icmp type 3 reply. And at the very last night, we got some pretty clever suggestions from my friends, and got that part fixed :)

- htons is sort of annoying. It gave us lots of troubles when we just couldn't get the correct icmp reply understood by the server. Finally we figured it out and celebrated for 1 second on our discovery :)

- The debugging printhdr is handy. It helps us figure out the packet we formed or obtained. 




/ ################# Harvest ################# /
In order to complete this assignment, we spent several late nights on debugging.... It was extremely painful, and sometimes even despairing :( The thing to complain about is that there are SO MANY details and ambiguities existing in this assignment. It makes the bugs extremely hard to find out. But at the end of the day, when the assignment was almost nailed down, we became quite clear about the total process on how the packets are controlled in the router, at least for arp and ip creation and response!!!! It is expected that our simple router will work for a1, and will handle tasks properly if it will be used in a2 ... 