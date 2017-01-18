
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <regex.h>

#define TCP_NUM 6
/* returns packet id */

regex_t regex;
const char *pattern = "Host: www.sex.com";
int ret_reg;

void hex_dump(unsigned char* buf, int size)
{
	for (int i = 0; i < size; i++) {
		if(i % 16 == 0) {
			printf("\n");
		}
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

static u_int32_t print_pkt (struct nfq_data *tb, int *drop)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
	
		printf("payload_len=%d\n", ret);
		hex_dump(data, ret);
		struct iphdr* dump_ip = (struct iphdr*) data;
		if(dump_ip->protocol == TCP_NUM) {
			struct tcphdr* dump_tcp = (struct tcphdr*) ((void*) dump_ip + (dump_ip->ihl) * 4);
			char* http = (char*) ((void*) dump_tcp + (dump_tcp->doff) * 4);
			unsigned short total_length = (dump_ip->tot_len>>8) | (dump_ip->tot_len<<8);
			int data_len = total_length - (dump_ip->ihl * 4) - (dump_tcp->doff * 4);
			//printf("total_length: %hd\n", total_length);
			//printf("ip_header length: %d\n", dump_ip->ihl * 4);
			//printf("tcp length: %d\n", dump_tcp->doff * 4);
			//printf("data_len: %d\n", data_len);
			printf("%s\n", http);
			
			ret_reg = regexec(&regex, http, 0, NULL, 0);
			if (!ret_reg) {		
				printf("Match\n");
				*drop = 1;
			}
			else if (ret_reg == REG_NOMATCH) {
				printf("NO MATCH\n");
			}
			else {
				*drop = 1;
				printf("MATCH FAIL\n");
			}
			
		}
		else {
			printf("it is not tcp packet\n");
		}
	}

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int drop = 0;
	u_int32_t id = print_pkt(nfa, &drop);
	printf("entering callback\n");
	if(drop)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	/* REGEX COMPILE */
	ret_reg = regcomp(&regex, pattern, 0);
	if (ret_reg) {
		printf("Could not compile regex\n");
		exit(1);
	} 
	
	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	regfree(&regex);	
	exit(0);
}
