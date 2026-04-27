#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

char *blocked_host;

static u_int32_t get_packet_id(struct nfq_data *nfa) {
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
        return ntohl(ph->packet_id);
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = get_packet_id(nfa);

    unsigned char *payload;
    int len = nfq_get_payload(nfa, &payload);

    if (len >= 0) {
        struct iphdr *ip = (struct iphdr *)payload;
	if (ip->protocol != IPPROTO_TCP)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	int ip_header_len = ip->ihl * 4;
       
        struct tcphdr *tcp = (struct tcphdr *)(payload + ip_header_len);
	if (ntohs(tcp->dest) != 80)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        int tcp_header_len = tcp->doff * 4;
        unsigned char *http = payload + ip_header_len + tcp_header_len;

        if (http >= payload + len)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        if (memcmp(http, "GET", 3) != 0 &&
            memcmp(http, "POST", 4) != 0)
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        char *host = strstr((char *)http, "Host: ");
        if (host) {
            host += 6;

            char *end = strstr(host, "\r\n");
            if (end) {
                char domain[256] = {0};
                int host_len = end - host;

                if (host_len < sizeof(domain)) {
                    strncpy(domain, host, host_len);

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
