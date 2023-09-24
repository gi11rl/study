#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
    
    /* 1. Ethernet Header */
    struct ethheader *eth = (struct ethheader *)packet;
    const unsigned int eth_header_len = 14;
    
    u_char *src = eth->ether_shost;
    u_char *dst = eth->ether_dhost;

        // src mac
    printf("[MAC] From: ");
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", src[0], src[1], src[2], src[3], src[4], src[5]);

        // dst mac
    printf("[MAC] To: " );
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);

    
    /* 2. IP Header */
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *)
                            (packet + sizeof(struct ethheader)); 
        unsigned int ip_header_len = (ip -> iph_ihl) * 4;
        unsigned short int datagram_len= ntohs(ip -> iph_len);

        printf("[IP] From: %s\n", inet_ntoa(ip->iph_sourceip)); // src IP  
        printf("[IP] To: %s\n", inet_ntoa(ip->iph_destip)); // dst IP

    /* 3. TCP Header */
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader * tcp = (struct tcpheader *) (packet + sizeof(struct ethheader) + ip_header_len);
            unsigned int tcp_header_len = TH_OFF(tcp) * 4;

            printf("[TCP] From: %d\n", ntohs(tcp->tcp_sport)); // src port
            printf("[TCP] To: %d\n", ntohs(tcp->tcp_dport)); // dst port

    /* 4. Message */
            // message len = datagram len - ip header - tcp header
            unsigned int message_len = datagram_len - ip_header_len - tcp_header_len;
            
            if (message_len != 0) {

                char* message = (char*) malloc (sizeof(char) * message_len);
                char* tmp = (char*) (packet + eth_header_len + ip_header_len + tcp_header_len);
                memcpy(message, tmp, message_len);

                printf("[Message] : %s\n", message); // message
                free(message);

            }
        }
    
    }
    
    printf("\n");
    return;
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}