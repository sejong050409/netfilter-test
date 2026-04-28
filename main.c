#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "headers.h"

char *blocked_host;

static u_int32_t print_pkt (struct nfq_data *tb)
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
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);

    unsigned char *payload;
    int len = nfq_get_payload(nfa, &payload);

    if (len >= 0) {
        ip_header *ip = (ip_header *)payload;
	int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

	if (ip->protocol != 6)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
       
        tcp_header *tcp = (tcp_header *)(payload + ip_header_len);
	if (ntohs(tcp->dst_port) != 80)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        int tcp_header_len = ((tcp->offset_reserved >> 4) & 0x0F) * 4;        
	
	unsigned char *http = payload + ip_header_len + tcp_header_len;

        if (http >= payload + len)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        char *host = strcasestr((char *)http, "Host:");
        if (host) {
            host += 5;
	    while (*host == ' ') host++;

            char *end = strstr(host, "\r\n");
            if (end) {
                char domain[256] = {0};
                int host_len = end - host;

                if (host_len < sizeof(domain)) {
                    strncpy(domain, host, host_len);
		    domain[host_len] = '\0';

                    printf("[HTTP Host] %s\n", domain); 
                    if (strcmp(domain, blocked_host) == 0) {
                        printf(">>> BLOCKED: %s\n", domain);
                        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("syntax: netfilter-test <host>\n");
        printf("example: netfilter-test test.gilgil.net\n");
        return -1;
    }

    blocked_host = argv[1];

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096];

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
