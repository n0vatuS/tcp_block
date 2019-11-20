#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <errno.h>
#include <string>
#include <pcap.h>

#define HW_ADDR_LEN 	6
#define IP_ADDR_LEN 	4
#define TYPE_IPV4  0x0800
#define PTC_TCP    	6

typedef struct eth_hdr {
    uint8_t dst_addr[HW_ADDR_LEN];
    uint8_t src_addr[HW_ADDR_LEN];
    uint16_t eth_type;
} ETHER;

typedef struct ip_hdr {
    uint8_t iph_ihl:4, ip_ver:4;
    uint8_t iph_tos;
    uint16_t iph_len;
    uint16_t iph_ident;
    uint8_t iph_flags;
    uint16_t iph_offset;
    uint8_t iph_ttl;
    uint8_t iph_protocol;
    uint16_t iph_chksum;
    uint8_t iph_source[IP_ADDR_LEN], iph_dest[IP_ADDR_LEN];
} IP;

typedef struct tcp_hdr {
    uint16_t tcph_srcport;
    uint16_t tcph_destport;
    uint32_t tcph_seqnum;
    uint32_t tcph_acknum;
    uint8_t tcph_reserved:4, tcph_offset:4;
    uint8_t tcph_flags;
    uint16_t tcph_win;
    uint16_t tcph_chksum;
    uint16_t tcph_urgptr;
} TCP;

typedef struct header {
	ETHER eth_hdr;
	IP ip_hdr;
	TCP tcp_hdr;
} header;

uint16_t ipChecksum(IP ip_hdr);
uint16_t tcpChecksum(IP ip_hdr, TCP tcp_hdr);

int forwardRST(pcap_t * handle, const u_char * pkt);
int backwardRST(pcap_t * handle, const u_char * pkt);
int forwardFIN(pcap_t * handle, const u_char * pkt);
int backwardFIN(pcap_t * handle, const u_char * pkt);

void blockPacket(pcap_t * handle, struct pcap_pkthdr * header, const u_char * pkt_data);


