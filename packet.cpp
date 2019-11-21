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
    pseudo_hdr * header = (pseudo_hdr *)malloc(sizeof(pseudo_hdr));
    memcpy(header->ip_src, ip_hdr->iph_src, IP_ADDR_LEN);
    memcpy(header->ip_dst, ip_hdr->iph_dst, IP_ADDR_LEN);
    header->reserved = 0x00;
    header->protocol = ip_hdr->iph_protocol;
    header->tcp_len = htons(ntohs(ip_hdr->iph_len) - sizeof(IP));
    tcp_hdr->tcph_chksum = 0;
    uint32_t checksum = 0;
    printf("%02x %02x %02x %02x %02x\n", ip_hdr->iph_src[0], header->ip_src[0], header->reserved, header->protocol, header->tcp_len);
    for(int i=0; i<sizeof(pseudo_hdr)/sizeof(uint16_t); i++) {
 	printf("%d\n",i);
	checksum += ntohs(*((uint16_t *)header+i));
	printf("%02x\n",ntohs(*((uint16_t *)header+i)));
	printf("cksum : %02x\n", checksum);
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
	printf("cksum : %02x\n", checksum);
    }
    for(int i=0; i<(tcp_hdr->tcph_offset * 4)/sizeof(uint16_t); i++) {
	checksum += *((uint16_t *)tcp_hdr+i);
	printf("%02x\n",*((uint16_t *)tcp_hdr+i));
	printf("cksum : %02x\n", checksum);
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
	printf("cksum : %02x\n", checksum);
	//printf("cksum : %d\n", checksum);
    }

    free(header);
    return (uint16_t)(~checksum);
}

void sendPacket(pcap_t * handle, const u_char * pkt_data, int pkt_len, DIR dir, int flag){
    u_char packet[pkt_len];
    memcpy(packet, pkt_data, pkt_len);

    ETHER * eth_hdr = (ETHER *)packet;
    IP * ip_hdr = (IP *)packet + ETHER_HDR_LEN;
    TCP * tcp_hdr = (TCP *)(packet + ETHER_HDR_LEN + ip_hdr->iph_ihl * 4);
    if(flag == RST)
    	tcp_hdr->tcph_flags |= flag;
    else if(flag == FIN)
	tcp_hdr->tcph_flags |= (flag | ACK);

    if(dir == BW) {
	swap(eth_hdr->src_addr, eth_hdr->dst_addr, HW_ADDR_LEN); // swap mac address
	swap(ip_hdr->iph_src, ip_hdr->iph_dst, IP_ADDR_LEN); // swap ip address
	swap((uint8_t *)&tcp_hdr->tcph_srcport, (uint8_t *)&tcp_hdr->tcph_dstport, 2); // swap port
	ip_hdr->iph_chksum = htons(ipChecksum(ip_hdr));
    }

    //tcp_hdr->tcph_chksum = htons(tcpChecksum(ip_hdr, tcp_hdr));

    int res = pcap_sendpacket(handle, (const u_char*)packet, pkt_len);

    if(res == 0)
	printf("[+] Send packet success!\n");
    else
	printf("[-] Send packet fail!\n");
}

void blockPacket(pcap_t * handle, struct pcap_pkthdr * header, const u_char * pkt_data, char * host){
    ETHER * eth_hdr = (ETHER *)pkt_data;
    IP * ip_hdr = (IP *)(pkt_data + ETHER_HDR_LEN);
    TCP * tcp_hdr = (TCP *)(pkt_data + ETHER_HDR_LEN + ip_hdr->iph_ihl * 4);
    
    if (ntohs(eth_hdr->eth_type) != TYPE_IPV4||
	ip_hdr->iph_protocol != PTC_TCP||
	tcp_hdr->tcph_flags & (RST | FIN))
        return;
    
    printf("%x%x%x%x %x%x%x%x\n", ip_hdr->iph_src[0], ip_hdr->iph_src[1], ip_hdr->iph_src[2], ip_hdr->iph_src[3], ip_hdr->iph_dst[0],ip_hdr->iph_dst[1],ip_hdr->iph_dst[2],ip_hdr->iph_dst[3]);
    printf("%0d ", tcp_hdr->tcph_chksum);
    printf("%0d\n", tcpChecksum(ip_hdr,tcp_hdr));
    int tcp_len = ETHER_HDR_LEN + (ip_hdr->iph_ihl) * 4 + (tcp_hdr->tcph_offset) *  4;

    if(tcp_len >= header->caplen || !(compare_method(pkt_data + tcp_len) && check_host(pkt_data + tcp_len, host))) return;

    sendPacket(handle, pkt_data, header->caplen, FW, RST);
    sendPacket(handle, pkt_data, header->caplen, BW, RST);
}
