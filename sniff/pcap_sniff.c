#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "hacking.h"

void pcap_fatal(const char *failed_in, const char *errbuf){
  printf("Fatal Error in %s: %s\n", failed_in, errbuf);
  exit(1);
}

int main(void){
  struct pcap_pkthdr header;
  const u_char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  pcap_t *pcap_handle;
  int i;

  device = pcap_lookupdev(errbuf);
  //device = loopback;
  if (device == NULL)
    pcap_fatal("pcap_lookupdev", errbuf);

  printf("Sniffing on device %s\n", device);

  pcap_handle = pcap_open_live(device, 4096, 1, 2000, errbuf);
  if (pcap_handle == NULL)
    pcap_fatal("pcap_open_live", errbuf);


//  printf("%d", pcap_datalink(pcap_handle));
  if (pcap_datalink(pcap_handle) != DLT_EN10MB){
	  printf("lull");
  } else {
	  printf("jaadu");
  }

  for (i=0; i<20; i++){
    packet = pcap_next(pcap_handle, &header);
    printf("Got a %d byte packet\n", header.len);
    dump(packet, header.len);
  }
  pcap_close(pcap_handle);
}
