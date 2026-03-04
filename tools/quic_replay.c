#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pcap/pcap.h>

#define SLL_V1_HDR_LEN 16U
#define SLL_V2_HDR_LEN 20U

typedef struct replay_cfg_s {
    const char *pcap_file;
    const char *dst_ip;
    uint16_t dst_port;
    uint16_t src_port;
    double speed;
    uint32_t loops;
} replay_cfg_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -r <capture.pcap> -d <dst_ip> -p <dst_port> "
            "[-s <src_port>] [-x <speed>] [-l <loops>]\n",
            prog);
}

static uint64_t monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_until_ns(uint64_t target_ns)
{
    struct timespec ts;

    ts.tv_sec = (time_t)(target_ns / 1000000000ULL);
    ts.tv_nsec = (long)(target_ns % 1000000000ULL);

    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
        /* Retry on signal interruption. */
    }
}

static int extract_udp_payload(const u_char *packet,
                               uint32_t caplen,
                               int datalink,
                               const u_char **payload,
                               uint16_t *payload_len)
{
    uint32_t l2_len = 0;
    const struct iphdr *iph;
    uint32_t ip_hl;
    const struct udphdr *udph;
    uint16_t udp_len;
    uint32_t avail_len;

    if (packet == NULL || payload == NULL || payload_len == NULL) {
        return -1;
    }

    switch (datalink) {
    case DLT_EN10MB:
        if (caplen < sizeof(struct ether_header)) {
            return -1;
        }
        {
            const struct ether_header *eth = (const struct ether_header *)packet;
            if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
                return -1;
            }
        }
        l2_len = sizeof(struct ether_header);
        break;

    case DLT_LINUX_SLL:
        if (caplen < SLL_V1_HDR_LEN || ntohs(*(const uint16_t *)(packet + 14U)) != ETHERTYPE_IP) {
            return -1;
        }
        l2_len = SLL_V1_HDR_LEN;
        break;

    case DLT_LINUX_SLL2:
        if (caplen < SLL_V2_HDR_LEN || ntohs(*(const uint16_t *)packet) != ETHERTYPE_IP) {
            return -1;
        }
        l2_len = SLL_V2_HDR_LEN;
        break;

    case DLT_RAW:
        l2_len = 0;
        break;

    default:
        return -1;
    }

    if (caplen < l2_len + sizeof(struct iphdr)) {
        return -1;
    }

    iph = (const struct iphdr *)(packet + l2_len);
    if (iph->version != 4 || iph->protocol != IPPROTO_UDP) {
        return -1;
    }

    ip_hl = (uint32_t)iph->ihl * 4U;
    if (ip_hl < sizeof(struct iphdr) || caplen < l2_len + ip_hl + sizeof(struct udphdr)) {
        return -1;
    }

    udph = (const struct udphdr *)(packet + l2_len + ip_hl);
    udp_len = ntohs(udph->uh_ulen);
    if (udp_len < sizeof(struct udphdr)) {
        return -1;
    }

    avail_len = caplen - l2_len - ip_hl - (uint32_t)sizeof(struct udphdr);
    if (avail_len == 0) {
        return -1;
    }

    *payload = packet + l2_len + ip_hl + sizeof(struct udphdr);
    *payload_len = (uint16_t)((udp_len - sizeof(struct udphdr) < avail_len)
                                  ? (udp_len - sizeof(struct udphdr))
                                  : avail_len);

    return (*payload_len > 0) ? 0 : -1;
}

static int replay_once(int sockfd, const struct sockaddr_in *dst, const replay_cfg_t *cfg)
{
    pcap_t *pc;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    const u_char *packet;
    struct pcap_pkthdr *hdr;
    int datalink;
    int rc;
    uint64_t first_ts_us = 0;
    uint64_t start_ns = monotonic_ns();
    uint64_t sent_pkts = 0;

    pc = pcap_open_offline(cfg->pcap_file, errbuf);
    if (pc == NULL) {
        fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
        return -1;
    }

    datalink = pcap_datalink(pc);

    while ((rc = pcap_next_ex(pc, &hdr, &packet)) >= 0) {
        const u_char *udp_payload;
        uint16_t udp_payload_len;
        uint64_t ts_us;
        uint64_t rel_us;
        uint64_t target_ns;

        if (rc == 0) {
            continue;
        }

        if (extract_udp_payload(packet, hdr->caplen, datalink, &udp_payload, &udp_payload_len) != 0) {
            continue;
        }

        ts_us = (uint64_t)hdr->ts.tv_sec * 1000000ULL + (uint64_t)hdr->ts.tv_usec;
        if (first_ts_us == 0) {
            first_ts_us = ts_us;
        }

        rel_us = ts_us - first_ts_us;
        target_ns = start_ns + (uint64_t)(((double)rel_us * 1000.0) / cfg->speed);
        sleep_until_ns(target_ns);

        if (sendto(sockfd,
                   udp_payload,
                   udp_payload_len,
                   0,
                   (const struct sockaddr *)dst,
                   sizeof(*dst)) < 0) {
            perror("sendto");
            pcap_close(pc);
            return -2;
        }

        sent_pkts++;
    }

    if (rc == -1) {
        fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pc));
        pcap_close(pc);
        return -3;
    }

    pcap_close(pc);
    fprintf(stdout, "replay_once sent %llu UDP payloads\n", (unsigned long long)sent_pkts);
    return 0;
}

int main(int argc, char **argv)
{
    replay_cfg_t cfg;
    int opt;
    int sockfd;
    struct sockaddr_in dst;
    uint32_t i;

    memset(&cfg, 0, sizeof(cfg));
    cfg.speed = 1.0;
    cfg.loops = 1;

    while ((opt = getopt(argc, argv, "r:d:p:s:x:l:h")) != -1) {
        switch (opt) {
        case 'r':
            cfg.pcap_file = optarg;
            break;
        case 'd':
            cfg.dst_ip = optarg;
            break;
        case 'p':
            cfg.dst_port = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 's':
            cfg.src_port = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 'x':
            cfg.speed = strtod(optarg, NULL);
            break;
        case 'l':
            cfg.loops = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (cfg.pcap_file == NULL || cfg.dst_ip == NULL || cfg.dst_port == 0 ||
        cfg.speed <= 0.0 || cfg.loops == 0) {
        usage(argv[0]);
        return 1;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    if (cfg.src_port != 0U) {
        struct sockaddr_in src;
        memset(&src, 0, sizeof(src));
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = htonl(INADDR_ANY);
        src.sin_port = htons(cfg.src_port);
        if (bind(sockfd, (const struct sockaddr *)&src, sizeof(src)) < 0) {
            perror("bind");
            close(sockfd);
            return 1;
        }
    }

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(cfg.dst_port);
    if (inet_pton(AF_INET, cfg.dst_ip, &dst.sin_addr) != 1) {
        fprintf(stderr, "invalid dst ip: %s\n", cfg.dst_ip);
        close(sockfd);
        return 1;
    }

    for (i = 0; i < cfg.loops; ++i) {
        int rc = replay_once(sockfd, &dst, &cfg);
        if (rc != 0) {
            close(sockfd);
            return 1;
        }
    }

    close(sockfd);
    return 0;
}
