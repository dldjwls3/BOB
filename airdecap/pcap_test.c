#include <stdio.h>
#include <pcap.h>

#define BUFSIZE 1000
#define promisc 1
#define timeout_ms 1000

int main(int argc, char *argv[])
{
	char src_dev = "wlp2s0";
	char dest_dev = "TEST";
	char errbuf[1000];

	pcap_t *handle_in = pcap_open_live(src_dev, BUFSIZE, promisc, timeout_ms, errbuf);
	if (handle_in == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	pcap_t *handle_out = pcap_open_live(dest_dev, BUFSIZE, promisc, timeout_ms, errbuf);
	if (handle_out == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}


	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	packet = pcap_next(handle, &header);
	
	/* Send down the packet */
	if (pcap_sendpacket(handle_out, packet, 100) != 0) {
		fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		return 2;
	}
	return 0;
}
