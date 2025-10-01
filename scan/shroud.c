#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>

#include "hacking.h"

#define MAX_EXISTING_PORTS 30

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int set_packet_filter(pcap_t *, struct in_addr *, u_short *);

struct data_pass{
  libnet_t *l;
  u_char *packet;
};

int main(int argc, char **argv){
  libnet_t *l;
  struct pcap_pkthdr cap_header;
  const u_char *packet, *pkt_data;
  pcap_t *pcap_handle;
  char errbuf[PCAP_ERRBUF_SIZE];  // Same size as LIBNET_ERRBUF_SIZE
  char *device;
  u_long target_ip;
  int network, i;
  struct data_pass critical_libnet_data;
  u_short existing_ports[MAX_EXISTING_PORTS+2];
  char payload[] = "aaaaaaaaaaaaaaaaaaaaaa";

  if ((argc < 2) || (argc > MAX_EXISTING_PORTS+2)){
    if (argc > 2)
      printf("Limited to tracking %d existing ports.\n", MAX_EXISTING_PORTS);
    else
      printf("Usage: %s <IP to shroud> [existing ports...]\n", argv[0]);
    exit(0);
  }

  if ((device = pcap_lookupdev(errbuf)) == NULL)
    fatal(errbuf);
  
  if ((l = libnet_init(LIBNET_RAW4, device, errbuf)) == NULL)
    fatal(errbuf);

  if ((target_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE)) == -1)
    fatal("Invalid target address");

  for (i=2; i<argc; i++)
    existing_ports[i-2] = (u_short) atoi(argv[i]);

  existing_ports[argc-2] = 0;

  if ((pcap_handle = pcap_open_live(device, 65535, 1, -1, errbuf)) == NULL)
    fatal(errbuf);

  critical_libnet_data.l = l;
  critical_libnet_data.packet = payload;

  libnet_seed_prand(l);

  set_packet_filter(pcap_handle, (struct in_addr *)&target_ip, existing_ports);

  pcap_loop(pcap_handle, -1, caught_packet, (u_char *)&critical_libnet_data);
  pcap_close(pcap_handle);
}

/* Sets a packet filter to look for established TCP connections to target_ip */
int set_packet_filter(pcap_t *pcap_hdl, struct in_addr *target_ip, u_short *ports){
  struct bpf_program filter;
  char *str_ptr, filter_string[90 + (25 * MAX_EXISTING_PORTS)];
  int i = 0;

  sprintf(filter_string, "dst host %s and ", inet_ntoa(*target_ip));
  strcat(filter_string, "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0");
  if (ports[0] != 0){
    str_ptr = filter_string + strlen(filter_string);
    if (ports[1] == 0)
      sprintf(str_ptr, " and not dst port %hu", ports[i]);
    else{
      sprintf(str_ptr, " and not (dst port %hu", ports[i++]);
      while(ports[i] != 0){
	str_ptr = filter_string + strlen(filter_string);
	sprintf(str_ptr, " or dst port %hu", ports[i++]);
      }
      strcat(filter_string, ")");
    }
  }
  printf("DEBUG: filter string is \'%s\'\n", filter_string);
  if (pcap_compile(pcap_hdl, &filter, filter_string, 1, 0) == -1)
    fatal("pcap_compile failed");

  if (pcap_setfilter(pcap_hdl, &filter) == -1)
    fatal("pcap_setfilter failed");
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet){
  static unsigned long count = 0;
  printf("[+] got packet #%lu\n", ++count);
  u_char *pkt_data;
  struct libnet_ipv4_hdr *IPhdr;
  struct libnet_tcp_hdr *TCPhdr;
  struct data_pass *passed;
  int bcount;

  passed = (struct data_pass *) user_args;


  IPhdr = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
  TCPhdr = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + (IPhdr->ip_hl * 4));

  libnet_build_tcp(ntohs(TCPhdr->th_dport),
		   ntohs(TCPhdr->th_sport),
		   htonl(libnet_get_prand(LIBNET_PRu32)),
		   htonl(ntohl(TCPhdr->th_seq) + 1),
		   TH_SYN | TH_ACK,
		   libnet_get_prand(LIBNET_PRu16),
		   0,
		   0,
		   LIBNET_TCP_H,
		   NULL,
		   0,
		   passed->l,
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
		    passed->l,
		    0);

  if (libnet_write(passed->l) == -1)
    fatal(libnet_geterror(passed->l));

  libnet_clear_packet(passed->l);
  printf("bing\n");
}
