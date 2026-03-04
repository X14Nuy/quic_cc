#include "microburst_scheduler.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -i <iface> -d <dst_ip> -p <dst_port> [options]\n"
            "Options:\n"
            "  -e <entropy.bin>   external entropy file for CID/padding\n"
            "  -n <packets>       packets per micro-burst (default 8)\n"
            "  -w <window_ms>     trigger window in ms (default 200)\n"
            "  -t <threshold>     trigger packet threshold (default 20)\n"
            "  -c <cid_len>       CID length 1..20 (default 16)\n"
            "  -m <max_iat_ms>    IAT histogram max ms (default 5000)\n"
            "  -r <rebuild_pkts>  alias rebuild interval (default 256)\n"
            "  -F <profile_bpf>   profile capture filter\n"
            "  -T <trigger_bpf>   trigger capture filter\n",
            prog);
}

static int read_all_bytes(const char *path, uint8_t **buf, size_t *len)
{
    FILE *fp;
    long sz;
    uint8_t *data;

    if (path == NULL || buf == NULL || len == NULL) {
        return -1;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return -2;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -3;
    }
    sz = ftell(fp);
    if (sz <= 0) {
        fclose(fp);
        return -4;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -5;
    }

    data = (uint8_t *)malloc((size_t)sz);
    if (data == NULL) {
        fclose(fp);
        return -6;
    }

    if (fread(data, 1, (size_t)sz, fp) != (size_t)sz) {
        free(data);
        fclose(fp);
        return -7;
    }

    fclose(fp);
    *buf = data;
    *len = (size_t)sz;
    return 0;
}

int main(int argc, char **argv)
{
    microburst_scheduler_cfg_t cfg;
    microburst_scheduler_t *sch = NULL;
    const char *entropy_path = NULL;
    int opt;

    memset(&cfg, 0, sizeof(cfg));

    while ((opt = getopt(argc, argv, "i:d:p:e:n:w:t:c:m:r:F:T:h")) != -1) {
        switch (opt) {
        case 'i':
            cfg.iface = optarg;
            break;
        case 'd':
            cfg.dst_ip = optarg;
            break;
        case 'p':
            cfg.dst_port = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 'e':
            entropy_path = optarg;
            break;
        case 'n':
            cfg.microburst_packets = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'w':
            cfg.trigger_window_ms = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 't':
            cfg.trigger_pkt_threshold = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'c':
            cfg.cid_len = (uint16_t)strtoul(optarg, NULL, 10);
            break;
        case 'm':
            cfg.max_iat_ms = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'r':
            cfg.alias_rebuild_interval = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'F':
            cfg.profile_bpf = optarg;
            break;
        case 'T':
            cfg.trigger_bpf = optarg;
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (cfg.iface == NULL || cfg.dst_ip == NULL || cfg.dst_port == 0U) {
        usage(argv[0]);
        return 1;
    }

    if (signal(SIGINT, on_signal) == SIG_ERR || signal(SIGTERM, on_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    if (mbs_create(&sch, &cfg) != 0) {
        fprintf(stderr, "mbs_create failed\n");
        return 1;
    }

    if (entropy_path != NULL) {
        uint8_t *entropy = NULL;
        size_t entropy_len = 0;

        if (read_all_bytes(entropy_path, &entropy, &entropy_len) != 0) {
            fprintf(stderr, "failed to read entropy file: %s\n", entropy_path);
            mbs_destroy(sch);
            return 1;
        }

        if (mbs_set_entropy(sch, entropy, entropy_len) != 0) {
            fprintf(stderr, "mbs_set_entropy failed\n");
            free(entropy);
            mbs_destroy(sch);
            return 1;
        }
        free(entropy);
    }

    if (mbs_start(sch) != 0) {
        fprintf(stderr, "mbs_start failed\n");
        mbs_destroy(sch);
        return 1;
    }

    fprintf(stdout,
            "[module C] scheduler started on iface=%s, dst=%s:%u; Ctrl+C to stop\n",
            cfg.iface,
            cfg.dst_ip,
            cfg.dst_port);

    while (!g_stop) {
        sleep(1);
    }

    mbs_destroy(sch);
    return 0;
}
