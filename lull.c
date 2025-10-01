#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
  char *lull = "127.0.02";
  struct in_addr network_addr;
  inet_aton(lull, &network_addr);
  printf("%d\n", network_addr.s_addr);
  printf("%s\n", inet_ntoa(network_addr));
}
  
