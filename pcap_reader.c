//usage : ./pcap_reader <PCAP file name>
//e.g. : ./pcap_reader capture-1.pcap
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

#define ETHERNET_HDR_LEN 14

void sigproc(int sig) {

	printf("\nProcess aborted.");
	exit(0);
}

void parse_packet(const u_char *packetptr, const struct pcap_pkthdr header)
{
	struct ip* iphdr;		// Header structures
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	struct ether_header* etherhdr;
	unsigned short id, seq;		// ID and Sequence for ICMP packets
	u_char *ptr;
	int i;
 
	// Scan the data link layer
	etherhdr = (struct ether_header *) packetptr;

	printf("Ethernet header:\n");
	printf("\tSource MAC: %s",ether_ntoa((const struct ether_addr *)&etherhdr->ether_shost));
	printf("\tDestination MAC: %s ",ether_ntoa((const struct ether_addr *)&etherhdr->ether_dhost));

	if (ntohs (etherhdr->ether_type) == ETHERTYPE_IP) {
        	printf("\nNetwork header (IP) : \n");
	}
	else if (ntohs (etherhdr->ether_type) == ETHERTYPE_ARP) {
        	 printf("\nNetwork header (ARP) : \n");
		return;
     	}
	else if (ntohs (etherhdr->ether_type) == ETHERTYPE_REVARP) {
		printf("\nNetwork header (RARP) : \n");
		return;
	}
	else {
	        printf("\nNetwork header not IP or ARP\n");
         	return;
     	}


	// Scan the network layer
	packetptr += ETHERNET_HDR_LEN;
    
	iphdr = (struct ip*)packetptr;

	printf("\tSource IP : %s \t Destination IP : %s\n",inet_ntoa(iphdr->ip_src),inet_ntoa(iphdr->ip_dst));
	printf("\tID:%d TOS:0x%x TTL:%d IpHdrLen:%d TotalLen:%d Checksum:%d\n",ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,4*iphdr->ip_hl,ntohs(iphdr->ip_len),ntohs(iphdr->ip_sum));
 

	// Scan the transport layer, then parse and display
	// the fields based on the type of hearder: tcp, udp or icmp.
	packetptr += 4*iphdr->ip_hl;
	
	switch (iphdr->ip_p)
	{
		case IPPROTO_TCP:
		tcphdr = (struct tcphdr*)packetptr;
		printf("Transport header (TCP):\n\tSource port: %d\t Destination port: %d\n",ntohs(tcphdr->source),ntohs(tcphdr->dest));
	        printf("\tFlags : %c%c%c%c%c%c\tSeq: 0x%x Ack: 0x%x Window: 0x%x TcpLen: %d\n",
		(tcphdr->urg ? 'U' : '-'),
		(tcphdr->ack ? 'A' : '-'),
		(tcphdr->psh ? 'P' : '-'),
		(tcphdr->rst ? 'R' : '-'),
		(tcphdr->syn ? 'S' : '-'),
		(tcphdr->fin ? 'F' : '-'),
		ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),ntohs(tcphdr->window), 4*tcphdr->doff);
	        break;
	 
		case IPPROTO_UDP:
		udphdr = (struct udphdr*)packetptr;
		printf("Transport header (UDP):\n\tSource port: %d\tDestination port: %d\n",ntohs(udphdr->source),ntohs(udphdr->dest));
         	printf("\tLength: %d\tChecksum: %d\n",ntohs(udphdr->len),ntohs(udphdr->check));
         	break;
 	
     		case IPPROTO_ICMP:
		icmphdr = (struct icmphdr*)packetptr;
		printf("Transport header (ICMP):\n");
		memcpy(&id, (u_char*)icmphdr+4, 2);
		memcpy(&seq, (u_char*)icmphdr+6, 2);
		printf("\tType:%d Code:%d Checksum:%d ID:%d Sequence:%d\n", icmphdr->type, icmphdr->code,icmphdr->checksum,ntohs(id), ntohs(seq));
   		    break;

		default:
		printf("\tTransport header not identified.\n");
	}

	// Scanning packet finished
     	printf("------------------------------------------------------------\n\n");
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string if any operation fails
	struct pcap_pkthdr header;	// The header that pcap gives along with each packet
	const u_char *packet;		// The actual packet
	pcap_t *pcap;			// PCAP handle to read packets from
	int numpkts = 0;		// count of packets

	signal(SIGINT,sigproc);

	if(argc != 2)
	{
		printf("No input file supplied.");
		printf("\nUsage : ./pcap_reader <filename>\nExample : ./pcap_reader capture-1.pcap\n");
		return 1;
	}

	pcap = pcap_open_offline(argv[1], errbuf);
	if (pcap == NULL)
	{
		printf("error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	while ((packet = pcap_next(pcap, &header)) != NULL)
	{
		parse_packet(packet, header);
		numpkts++;
	}

	printf("%d packets shown from %s file.\n",numpkts,argv[1]);
	
	return 0;
}
