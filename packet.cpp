#include <stdio.h>
#include <iostream>
#include "packet.h"
#include "utils.h"
using namespace std;

void swap(uint8_t * a, uint8_t * b, int size) {
    uint8_t * temp = (uint8_t *)malloc(size);
    memcpy(temp, b, size);
    memcpy(b, a, size);
    memcpy(a, temp, size);
    free(temp);
}

uint16_t ipChecksum(IP * ip_hdr) {
    return 0;
}
uint16_t tcpChecksum(IP * ip_hdr, TCP * tcp_hdr) {
    return 0;
}

void sendPacket(pcap_t * handle, const u_char * pkt_data, int pkt_len, DIR dir, int flag){
    u_char packet[pkt_len];
    memcpy(packet, pkt_data, pkt_len);

    ETHER * eth_hdr = (ETHER *)packet;
    IP * ip_hdr = (IP *)packet + ETHER_HDR_LEN;
    TCP * tcp_hdr = (TCP *)(packet + ETHER_HDR_LEN + ((ip_hdr->iph_ihl) << 2));
    if(flag == RST)
    	tcp_hdr->tcph_flags |= flag;
    else if(flag == FIN)
	tcp_hdr->tcph_flags |= (flag | ACK);

    if(dir == BW) {
	swap(eth_hdr->src_addr, eth_hdr->dst_addr, HW_ADDR_LEN); // swap mac address
	swap((uint8_t *)ip_hdr->iph_src, (uint8_t *)ip_hdr->iph_dst, IP_ADDR_LEN); // swap ip address
	swap((uint8_t *)tcp_hdr->tcph_srcport, (uint8_t *)tcp_hdr->tcph_dstport, 2); // swap port
    }

    tcp_hdr->tcph_chksum = htons(tcpChecksum(ip_hdr, tcp_hdr));

    int res = pcap_sendpacket(handle, (const u_char*)packet, pkt_len);

    cout << " res=" << res << endl;
}

void blockPacket(pcap_t * handle, struct pcap_pkthdr * header, const u_char * pkt_data, char * host){
    ETHER * eth_hdr = (ETHER *)pkt_data;
    IP * ip_hdr = (IP *)(pkt_data + ETHER_HDR_LEN);
    TCP * tcp_hdr = (TCP *)(pkt_data + ETHER_HDR_LEN + ((ip_hdr->iph_ihl) << 2));
    printf("%02x, %02x %02x %02x\n",ip_hdr->iph_ihl,eth_hdr->eth_type,ip_hdr->iph_protocol,tcp_hdr->tcph_offset);
    if (ntohs(eth_hdr->eth_type) != TYPE_IPV4||
	ip_hdr->iph_protocol != PTC_TCP||
	tcp_hdr->tcph_flags & (RST | FIN))
        return;
    int tcp_len = 14 + (ip_hdr->iph_ihl) << 2 + (tcp_hdr->tcph_offset) << 2;
    printf("%02x %02x\n", ip_hdr->iph_ihl, tcp_hdr->tcph_offset);					
    if(!(compare_method(pkt_data + tcp_len) && check_host(pkt_data + tcp_len, host))) return;

    sendPacket(handle, pkt_data, header->caplen, FW, RST);
    sendPacket(handle, pkt_data, header->caplen, BW, FIN);
}
