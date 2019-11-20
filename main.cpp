#include <iostream>
#include <pcap.h>

#include "utils.h"
#include "packet.h"

using namespace std;

void usage() {
  printf("syntax : tcp_block <interface> <host>\n");
  printf("sample : tcp_block wlan0 test.gilgil.net\n");
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    usage();
    return -1;
  }

  char * dev = argv[1];
  char * host = argv[2];
  char errbuf[PCAP_ERRBUF_SIZE];
   
  cout << 1;
  pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  

  uint32_t netmask = 0xFFFFFF;
  bpf_program fcode;
  static const char * filter = "tcp";
  
  if (pcap_compile(handle, &fcode, filter, 1, netmask) < 0)
  {
    fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
    return -1;
  }
    
  if (pcap_setfilter(handle, &fcode) < 0)
  {
    fprintf(stderr,"\nError setting the filter.\n");
    return -1;
  }

  while (true) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res = pcap_next_ex(handle, &header, &pkt_data);
    if (res == 0) continue;
    if (res < 0) break;
    blockPacket(handle, header, pkt_data, host);
  }

  pcap_close(handle);
  return 0;
}

