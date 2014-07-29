//usage : sudo ./pfring_sniffer <interface name>
//e.g.  : sudo ./pfring_sniffer wlan0
#include <pcap.h>
#include <pfring.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

#define ETHERNET_HDR_LEN 14

pfring *handle;				// pfring Session handle
int filenumber = 1;				// global file number
char filenameprefix[] = "capture-";	// global file name prefix
char filename[20];			// global file name (combination of prefix + number)
FILE *capfile;				// global file pointer


void sigproc(int sig) {

	pfring_close(handle);
	close(capfile);
	printf("pfring closed.");

 	exit(0);
}

void makefilename()
{
	sprintf(filename,"%s%d",filenameprefix,filenumber);

	printf("\nNEW FILE NAME: %s",filename);
	fflush(stdout);
}

void parse_packet(const struct pfring_pkthdr *packethdr, const u_char *packetptr, const u_char *args)
{
	static int packetno = 0;

	packetno++;

	if(packetno>=100)
	{
		packetno = 0;
		close(capfile);

		filenumber++;
		makefilename();		
		if((capfile=fopen(filename,"wb"))==NULL) {
			printf("\nError opening %d th file.",filenumber);
			exit(1);
		}

	}

	fputs(packetptr,capfile);
	fputs("\n---\n",capfile);
}

int main(int argc, char *argv[])
{
	char *dev;			// The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string if any operation fails
	struct bpf_program fp;		// The compiled filter (not used)
	char filter_exp[] = "port 23";	// The filter expression (not used)
	bpf_u_int32 mask;		// Our subnet mask
	bpf_u_int32 net;		// Our network ID
	struct pfring_pkthdr header;	// The header that pfring gives us 
	const u_char *packet;		// The actual packet
	int flags;			// Flags to pass for opening pfring instance

	signal(SIGINT,sigproc);

	dev = argv[1];			// Set the device manually to arg[1]

  makefilename();

	if((capfile = fopen(filename,"wb")) == NULL) {
		printf("\nError opening capture file. Closing...");
		return 1;
	}

	flags = PF_RING_PROMISC;
	if((handle = pfring_open(dev, 500, flags)) == NULL) {  //MAX_CAPLEN instead of 500
   		printf("pfring_open error");
    		return(-1);
  	} else {
    		pfring_set_application_name(handle, "packetcapture");
	}

	pfring_enable_ring(handle);
		
	pfring_loop(handle,parse_packet,NULL,0);
		

	//pfring_close(handle);
	
	return 0;
}
