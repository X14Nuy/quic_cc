#include "traffic_profile.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -i <iface> [-f <bpf>] [-m <max_iat_ms>] [-r <rebuild_pkts>]\n",
            prog);
}

int main(int argc, char **argv)
{
    traffic_profile_engine_t eng;
    const char *iface = NULL;
    const char *bpf = "ip and udp";
    uint32_t max_iat_ms = 5000;
    uint32_t rebuild_pkts = 256;
    int opt;

    while ((opt = getopt(argc, argv, "i:f:m:r:h")) != -1) {
        switch (opt) {
        case 'i':
            iface = optarg;
            break;
        case 'f':
            bpf = optarg;
            break;
        case 'm':
            max_iat_ms = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'r':
            rebuild_pkts = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (iface == NULL) {
        usage(argv[0]);
        return 1;
    }

    if (signal(SIGINT, on_sigint) == SIG_ERR || signal(SIGTERM, on_sigint) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    if (tp_engine_init(&eng, max_iat_ms, rebuild_pkts) != 0) {
        fprintf(stderr, "tp_engine_init failed\n");
        return 1;
    }

    if (tp_engine_start_capture(&eng, iface, bpf, 2048, 1, 100) != 0) {
        fprintf(stderr, "tp_engine_start_capture failed\n");
        tp_engine_destroy(&eng);
        return 1;
    }

    printf("[module A] capture started on %s, press Ctrl+C to stop\n", iface);

    while (!g_stop) {
        uint16_t l;
        uint32_t d;
        int i;

        sleep(1);
        printf("packets=%llu | samples:",
               (unsigned long long)tp_engine_packet_count(&eng));
        for (i = 0; i < 5; ++i) {
            if (tp_engine_sample(&eng, &l, &d) == 0) {
                printf(" (L=%u,D=%ums)", l, d);
            }
        }
        printf("\n");
        fflush(stdout);
    }

    tp_engine_destroy(&eng);
    return 0;
}
