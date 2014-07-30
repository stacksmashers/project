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
#define PACKETS_PER_FILE 100		// Store 100 packets per capture file

pfring *handle;				// pfring Session handle
pcap_dumper_t *dumper = NULL;		// PCAP dump handler
int filenumber = 1;			// global file number
char filenameprefix[] = "capture-";	// global file name prefix
char filename[30];			// global file name (combination of prefix + number)

void sigproc(int sig) {

	pfring_close(handle);
	pfring_breakloop(handle);
	pcap_dump_close(dumper);

	printf("\nSniffer closed. %d files written to disk.\n",filenumber);

 	exit(0);
}

void makefilename()
{
	sprintf(filename,"%s%d.pcap",filenameprefix,filenumber);

	printf("\nNEW FILE NAME: %s\n",filename);
	fflush(stdout);
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
	u_char *packet;			// The actual packet
	int flags,num_pkts=0;		// Flags to pass for opening pfring instance, number of packets captured

	memset(&header,0,sizeof(header));
	signal(SIGINT,sigproc);

	dev = argv[1];			// Set the device manually to arg[1]
	printf("\nCapture device: %s\n", dev);

	makefilename();

	flags = PF_RING_PROMISC;
	if((handle = pfring_open(dev, 1520, flags)) == NULL) {  //MAX_CAPLEN instead of 1520
   		printf("pfring_open error");
    		return(-1);
  	} else {
    		pfring_set_application_name(handle, "packetcapture");
	}

	pfring_enable_ring(handle);

	dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384), filename);	//16384 is MTU
 	if(dumper == NULL) {
 		printf("Unable to create dump file %s\n", filename);
      		return(-1);
    	}

  	while(1) {
		if(pfring_recv(handle, &packet, 0, &header, 1 ) > 0) {	//wait for packet, blocking call

			if(num_pkts>=PACKETS_PER_FILE)
			{
				num_pkts = 0;
				pcap_dump_close(dumper);

				filenumber++;
				makefilename();		

				dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384), filename);
		 		if(dumper == NULL) {
		 			printf("Unable to create dump file %s\n", filename);
		      			exit(1);
		    		}

			}

			pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)&header, packet);
		  	fprintf(stdout, ".");
		  	fflush(stdout);
			
			num_pkts++;
    		}
  	}

	pcap_dump_close(dumper);
	pfring_close(handle);
			
	return 0;
}
