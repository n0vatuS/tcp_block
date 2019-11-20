#include "packet.h"

uint16_t ipChecksum(IP ip_hdr) {
	
}
uint16_t tcpChecksum(IP ip_hdr, TCP tcp_hdr) {
}

int forwardRST(pcap_t * handle, const u_char * pkt){
    return 0;
}

int backwardRST(pcap_t * handle, const u_char * pkt){
    return 0;
}
int forwardFIN(pcap_t * handle, const u_char * pkt){
    return 0;
}
int backwardFIN(pcap_t * handle, const u_char * pkt){
    return 0;
}

void blockPacket(pcap_t * handle, struct pcap_pkthdr * header, const u_char * pkt_data){
}
