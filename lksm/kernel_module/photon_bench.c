/*
 * photon_bench.c — Photon Ring end-to-end latency benchmark tool
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o photon_bench photon_bench.c -lssl -lcrypto -lm
 *
 * Usage:
 *   sudo ./photon_bench --key <32-byte-hex> [OPTIONS]
 *
 *   --key  HEX     32-byte master key as 64 hex characters (required)
 *   --dev  PATH    Device path            (default: /dev/photon_ring)
 *   --count N      Stop after N samples   (default: run until SIGINT)
 *   --warmup N     Discard first N frames (default: 10)
 *   --interval N   Print stats every N frames (default: 100)
 *   --csv  FILE    Append raw sample CSV to FILE (optional)
 *   --help
 *
 * What it measures
 * ────────────────
 * The kernel stamps event.dispatch_ts = ktime_get_real_ns() inside
 * photon_log_event() before the event enters the per-CPU ring buffer.
 * This tool records receive_ts = clock_gettime(CLOCK_REALTIME) immediately
 * after each read() returns, then decrypts the frame to extract dispatch_ts.
 *
 *   latency_ns = receive_ts − dispatch_ts
 *
 * This covers the full pipeline:
 *
 *   [detector fires]
 *       → photon_log_event (enqueue into per-CPU buffer)
 *       → flush_all_buffers
 *       → photon_encrypt_event (AES-GCM)
 *       → ring_buf_push into g_ring (cdev layer)
 *       → wake_up_interruptible
 *       → read() returns in userspace          ← receive_ts taken here
 *       → AES-GCM decryption in this tool
 *       → dispatch_ts extracted
 *
 * Statistics reported
 * ───────────────────
 *   min, max, mean, p50, p90, p95, p99, p99.9 (all in microseconds)
 *   plus a small ASCII histogram bucketed in 10 µs bands.
 *
 * Clock synchronisation note
 * ──────────────────────────
 * Both the kernel (ktime_get_real_ns) and this tool (CLOCK_REALTIME) read
 * the same underlying hardware clock via the vDSO on x86-64, so there is
 * no systematic offset between the two timestamps.  On other architectures
 * the vDSO mapping may introduce a negligible (<100 ns) jitter; this is
 * expected and does not affect the usefulness of the percentile data.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <sys/ioctl.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

/* ─────────────────────────────────────────────────── ioctl mirror ─────── */
#define PHOTON_KEY_SIZE       32
#define PHOTON_RING_DEV       "/dev/photon_ring"
#define PHOTON_RING_IOC_MAGIC 0xBE
#define PHOTON_IOC_SET_KEY    _IOW(PHOTON_RING_IOC_MAGIC, 1, uint8_t[32])

/* ─────────────────────────────────────────────────── crypto constants ─── */
#define PHOTON_IV_SIZE   12
#define PHOTON_TAG_SIZE  16

/* ─────────────────────────────────────────────────── photon_event mirror  */
/*
 * These sizes must exactly match the kernel struct photon_event declared in
 * include/event_manager.h (after the latency patch is applied).
 * If the kernel struct changes, update PHOTON_MAX_EVENT_DATA here too.
 */
#define PHOTON_MAX_EVENT_DATA  256
#define PHOTON_COMM_LEN         16

/*
 * Mirrors struct photon_event (packed) from include/event_manager.h.
 * The layout must be byte-for-byte identical so that the decrypted buffer
 * can be cast directly to this struct.
 */
typedef struct __attribute__((packed)) {
    uint64_t sequence_num;
    uint64_t timestamp_ns;
    uint32_t event_type;
    uint32_t detector_id;
    uint8_t  severity;
    uint8_t  _pad[3];
    uint32_t caller_pid;
    char     caller_comm[PHOTON_COMM_LEN];
    uint16_t data_len;
    uint8_t  data[PHOTON_MAX_EVENT_DATA];
    uint64_t dispatch_ts;
} photon_event_t;

/*
 * Mirrors struct photon_encrypted_msg from include/crypto.h.
 */
typedef struct __attribute__((packed)) {
    uint64_t sequence_num;
    uint64_t rotation_num;
    uint8_t  iv[PHOTON_IV_SIZE];
    uint16_t encrypted_len;
    uint8_t  auth_tag[PHOTON_TAG_SIZE];
    uint8_t  encrypted_data[];    /* encrypted_len bytes */
} photon_encrypted_msg_t;

/* Maximum raw frame bytes (matches PHOTON_FRAME_SLOT_SIZE in cdev_ch.c) */
#define MAX_FRAME_BYTES  8192

/* ─────────────────────────────────────────────────── HKDF helpers ──────── */

/*
 * hkdf_extract — HMAC-SHA256(salt, ikm) → prk
 */
static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm,  size_t ikm_len,
                         uint8_t *prk /* 32 bytes out */)
{
    unsigned int out_len = 32;
    return HMAC(EVP_sha256(), salt, (int)salt_len,
                ikm, (int)ikm_len, prk, &out_len) ? 0 : -1;
}

/*
 * hkdf_expand — produce okm_len bytes from prk + info using HKDF-Expand.
 * Mirrors the kernel implementation in crypto.c exactly.
 */
static int hkdf_expand(const uint8_t *prk,  size_t prk_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm,        size_t okm_len)
{
    uint8_t  t[32] = {0};
    size_t   pos   = 0;
    uint8_t  ctr   = 1;

    while (pos < okm_len) {
        EVP_MD_CTX  *ctx = EVP_MD_CTX_new();
        EVP_PKEY    *key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL,
                                                 prk, (int)prk_len);
        if (!ctx || !key) {
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(key);
            return -1;
        }

        EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
        if (ctr > 1)
            EVP_DigestSignUpdate(ctx, t, 32);
        if (info && info_len)
            EVP_DigestSignUpdate(ctx, info, info_len);
        EVP_DigestSignUpdate(ctx, &ctr, 1);

        size_t sig_len = 32;
        EVP_DigestSignFinal(ctx, t, &sig_len);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);

        size_t copy = okm_len - pos < 32 ? okm_len - pos : 32;
        memcpy(okm + pos, t, copy);
        pos += copy;
        ctr++;
    }
    memset(t, 0, sizeof(t));
    return 0;
}

/*
 * derive_session_key — mirrors photon_derive_session_key() in crypto.c.
 *
 * session_key = HKDF(master_key, rotation_num, "photon-ring-v1-<rotation>")
 */
static int derive_session_key(const uint8_t *master_key,
                               uint64_t       rotation_num,
                               uint8_t       *session_key /* 32 bytes out */)
{
    uint8_t prk[32];
    char    info[64];
    int     info_len;

    info_len = snprintf(info, sizeof(info), "photon-ring-v1-%llu",
                        (unsigned long long)rotation_num);

    if (hkdf_extract((const uint8_t *)&rotation_num, sizeof(rotation_num),
                     master_key, PHOTON_KEY_SIZE, prk) != 0)
        return -1;

    if (hkdf_expand(prk, sizeof(prk),
                    (const uint8_t *)info, (size_t)info_len,
                    session_key, PHOTON_KEY_SIZE) != 0)
        return -1;

    memset(prk,  0, sizeof(prk));
    memset(info, 0, sizeof(info));
    return 0;
}

/* ─────────────────────────────────────────────────── AES-GCM decrypt ───── */

/*
 * decrypt_event — AES-256-GCM decrypt one photon_encrypted_msg frame body.
 *
 * Returns 0 and writes into *event on success.
 * Returns -1 on auth failure or any OpenSSL error.
 */
static int decrypt_event(const uint8_t          *session_key,
                          const photon_encrypted_msg_t *enc,
                          photon_event_t         *event)
{
    EVP_CIPHER_CTX *ctx;
    int out_len = 0, final_len = 0;
    int ret = -1;

    if (enc->encrypted_len != sizeof(photon_event_t)) {
        fprintf(stderr, "[bench] unexpected encrypted_len=%u (want %zu)\n",
                enc->encrypted_len, sizeof(photon_event_t));
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, session_key, enc->iv) != 1)
        goto out;
    if (EVP_DecryptUpdate(ctx, (uint8_t *)event, &out_len,
                          enc->encrypted_data, (int)enc->encrypted_len) != 1)
        goto out;

    /* Set the expected auth tag before calling Final */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             PHOTON_TAG_SIZE,
                             (void *)enc->auth_tag) != 1)
        goto out;

    if (EVP_DecryptFinal_ex(ctx, (uint8_t *)event + out_len, &final_len) != 1) {
        fprintf(stderr, "[bench] AES-GCM auth tag mismatch — frame discarded\n");
        goto out;
    }

    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ─────────────────────────────────────────────────── statistics ─────────── */

#define MAX_SAMPLES  (1024 * 1024)

typedef struct {
    uint64_t *samples;       /* raw latencies in nanoseconds                */
    size_t    count;         /* number of valid samples stored               */
    uint64_t  sum_ns;        /* running sum for mean                        */
    uint64_t  min_ns;
    uint64_t  max_ns;
} latency_stats_t;

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void stats_init(latency_stats_t *s) {
    s->samples = malloc(MAX_SAMPLES * sizeof(uint64_t));
    if (!s->samples) { perror("malloc samples"); exit(1); }
    s->count  = 0;
    s->sum_ns = 0;
    s->min_ns = UINT64_MAX;
    s->max_ns = 0;
}

static void stats_record(latency_stats_t *s, uint64_t ns) {
    if (s->count < MAX_SAMPLES)
        s->samples[s->count++] = ns;
    s->sum_ns += ns;
    if (ns < s->min_ns) s->min_ns = ns;
    if (ns > s->max_ns) s->max_ns = ns;
}

/*
 * stats_percentile — returns the p-th percentile (0..100) in nanoseconds.
 * Sorts the sample array in place as a side effect.
 */
static uint64_t stats_percentile(latency_stats_t *s, double p) {
    if (s->count == 0) return 0;
    qsort(s->samples, s->count, sizeof(uint64_t), cmp_u64);
    size_t idx = (size_t)(p / 100.0 * (double)(s->count - 1) + 0.5);
    if (idx >= s->count) idx = s->count - 1;
    return s->samples[idx];
}

/*
 * print_histogram — ASCII histogram of latencies, bucketed in 10 µs bands.
 * Covers 0–200 µs; samples above 200 µs fall into an "overflow" bucket.
 */
static void print_histogram(latency_stats_t *s) {
#define HIST_BUCKET_US   10
#define HIST_BUCKETS     20
#define HIST_OVERFLOW    (HIST_BUCKETS)
#define HIST_TOTAL       (HIST_BUCKETS + 1)
#define HIST_BAR_WIDTH   40

    size_t counts[HIST_TOTAL] = {0};

    for (size_t i = 0; i < s->count; i++) {
        uint64_t us = s->samples[i] / 1000;
        size_t   b  = us / HIST_BUCKET_US;
        if (b >= HIST_BUCKETS) b = HIST_OVERFLOW;
        counts[b]++;
    }

    size_t peak = 0;
    for (int i = 0; i < HIST_TOTAL; i++)
        if (counts[i] > peak) peak = counts[i];

    printf("\n  Latency histogram (bucket = %d µs)\n", HIST_BUCKET_US);
    printf("  %-14s  %s\n", "Range (µs)", "Count");
    printf("  %-14s  %s\n", "──────────", "─────────────────────────────────────────");

    for (int i = 0; i < HIST_TOTAL; i++) {
        char label[32];
        if (i < HIST_BUCKETS)
            snprintf(label, sizeof(label), "%3d – %3d",
                     i * HIST_BUCKET_US, (i + 1) * HIST_BUCKET_US - 1);
        else
            snprintf(label, sizeof(label), ">= %3d  ",
                     HIST_BUCKETS * HIST_BUCKET_US);

        int bar_len = peak ? (int)((double)counts[i] / peak * HIST_BAR_WIDTH) : 0;
        printf("  %-14s  |%.*s%*s| %zu\n",
               label,
               bar_len,   "########################################",
               HIST_BAR_WIDTH - bar_len, "",
               counts[i]);
    }
    printf("\n");
}

/*
 * print_stats — full summary including percentiles and histogram.
 */
static void print_stats(latency_stats_t *s, size_t total_frames,
                         size_t warmup, size_t auth_errors) {
    if (s->count == 0) {
        printf("[bench] No samples recorded yet.\n");
        return;
    }

    double mean_us = (double)s->sum_ns / (double)s->count / 1000.0;

    printf("\n══════════════════════════════════════════════════════════\n");
    printf("  Photon Ring — End-to-End Latency Report\n");
    printf("  Frames read: %zu  Warmup discarded: %zu  Auth errors: %zu\n",
           total_frames, warmup, auth_errors);
    printf("  Samples recorded: %zu\n", s->count);
    printf("──────────────────────────────────────────────────────────\n");
    printf("  min     %8.2f µs\n", (double)s->min_ns / 1000.0);
    printf("  mean    %8.2f µs\n", mean_us);
    printf("  p50     %8.2f µs\n", (double)stats_percentile(s, 50.0)  / 1000.0);
    printf("  p90     %8.2f µs\n", (double)stats_percentile(s, 90.0)  / 1000.0);
    printf("  p95     %8.2f µs\n", (double)stats_percentile(s, 95.0)  / 1000.0);
    printf("  p99     %8.2f µs\n", (double)stats_percentile(s, 99.0)  / 1000.0);
    printf("  p99.9   %8.2f µs\n", (double)stats_percentile(s, 99.9)  / 1000.0);
    printf("  max     %8.2f µs\n", (double)s->max_ns / 1000.0);
    printf("══════════════════════════════════════════════════════════\n");

    print_histogram(s);
}

/* ─────────────────────────────────────────────────── CSV output ──────────── */

static void csv_append(FILE *csv, uint64_t seq, uint64_t dispatch_ts,
                        uint64_t receive_ts, uint64_t latency_ns) {
    fprintf(csv, "%llu,%llu,%llu,%llu\n",
            (unsigned long long)seq,
            (unsigned long long)dispatch_ts,
            (unsigned long long)receive_ts,
            (unsigned long long)latency_ns);
    fflush(csv);
}

/* ─────────────────────────────────────────────────── logging ────────────── */

static void log_ts(const char *level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void log_ts(const char *level, const char *fmt, ...) {
    char buf[256];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = gmtime(&ts.tv_sec);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);
    fprintf(stderr, "%s.%03ldZ [%s] ", buf, ts.tv_nsec / 1000000, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

#define LOG_INFO(...)  log_ts("INFO ", __VA_ARGS__)
#define LOG_WARN(...)  log_ts("WARN ", __VA_ARGS__)
#define LOG_ERROR(...) log_ts("ERROR", __VA_ARGS__)

/* ─────────────────────────────────────────────────── hex decode ─────────── */

static int hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/* ─────────────────────────────────────────────────── globals ────────────── */

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig) { (void)sig; g_running = 0; }

/* ─────────────────────────────────────────────────── usage ──────────────── */

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s --key HEX [OPTIONS]\n"
        "\n"
        "Required:\n"
        "  --key HEX      32-byte master key as 64 hex characters\n"
        "\n"
        "Options:\n"
        "  --dev  PATH    Device path              (default: /dev/photon_ring)\n"
        "  --count N      Stop after N samples     (default: run until SIGINT)\n"
        "  --warmup N     Discard first N frames   (default: 10)\n"
        "  --interval N   Print stats every N frames (default: 100)\n"
        "  --csv  FILE    Append raw sample CSV to FILE\n"
        "  --help\n"
        "\n"
        "The tool opens the device directly (no TLS relay) and must be run\n"
        "as root (CAP_SYS_ADMIN).  It decrypts each frame locally to extract\n"
        "the dispatch_ts field added by the latency kernel patch.\n",
        argv0);
}

/* ─────────────────────────────────────────────────── main ───────────────── */

int main(int argc, char *argv[]) {
    const char *dev        = PHOTON_RING_DEV;
    const char *key_hex    = NULL;
    const char *csv_path   = NULL;
    size_t      target     = 0;          /* 0 = run until SIGINT */
    size_t      warmup     = 10;
    size_t      interval   = 100;

    /* ── argument parsing ─────────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--key")      && i+1 < argc) key_hex  = argv[++i];
        else if (!strcmp(argv[i], "--dev")      && i+1 < argc) dev      = argv[++i];
        else if (!strcmp(argv[i], "--csv")      && i+1 < argc) csv_path = argv[++i];
        else if (!strcmp(argv[i], "--count")    && i+1 < argc) target   = (size_t)atol(argv[++i]);
        else if (!strcmp(argv[i], "--warmup")   && i+1 < argc) warmup   = (size_t)atol(argv[++i]);
        else if (!strcmp(argv[i], "--interval") && i+1 < argc) interval = (size_t)atol(argv[++i]);
        else if (!strcmp(argv[i], "--help"))  { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    if (!key_hex) {
        fprintf(stderr, "Error: --key is required.\n\n");
        usage(argv[0]);
        return 1;
    }

    uint8_t master_key[PHOTON_KEY_SIZE];
    if (hex_decode(key_hex, master_key, PHOTON_KEY_SIZE) != 0) {
        fprintf(stderr, "Error: --key must be exactly 64 hex characters.\n");
        return 1;
    }

    /* ── signal handlers ──────────────────────────────────────────────── */
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* ── open device (single fd used for both ioctl and read) ────────── */
    int dev_fd = open(dev, O_RDWR);
    if (dev_fd < 0) {
        LOG_ERROR("open(%s): %s", dev, strerror(errno));
        return 1;
    }
    LOG_INFO("Opened %s", dev);

    /* ── inject key into kernel (idempotent if already set) ───────────── */
    if (ioctl(dev_fd, PHOTON_IOC_SET_KEY, master_key) < 0 && errno != EEXIST) {
        LOG_ERROR("ioctl(PHOTON_IOC_SET_KEY): %s", strerror(errno));
        close(dev_fd);
        return 1;
    }
    LOG_INFO("Master key delivered to kernel (or already set)");

    /* ── open CSV file ────────────────────────────────────────────────── */
    FILE *csv = NULL;
    if (csv_path) {
        csv = fopen(csv_path, "a");
        if (!csv) {
            LOG_ERROR("fopen(%s): %s", csv_path, strerror(errno));
        } else {
            /* write header if file was empty */
            fseek(csv, 0, SEEK_END);
            if (ftell(csv) == 0)
                fprintf(csv, "sequence_num,dispatch_ts_ns,receive_ts_ns,latency_ns\n");
            LOG_INFO("CSV output: %s", csv_path);
        }
    }

    /* ── session key cache ────────────────────────────────────────────── */
    /*
     * Most frames use rotation 0.  Cache the last derived session key so we
     * don't re-derive on every frame unless the rotation number changes.
     */
    uint64_t cached_rotation = UINT64_MAX;   /* invalid sentinel */
    uint8_t  session_key[PHOTON_KEY_SIZE];

    /* ── statistics ───────────────────────────────────────────────────── */
    latency_stats_t stats;
    stats_init(&stats);

    static uint8_t frame_buf[MAX_FRAME_BYTES];
    size_t total_frames = 0;
    size_t auth_errors  = 0;
    size_t samples_done = 0;

    LOG_INFO("Bench loop starting (warmup=%zu interval=%zu target=%s)",
             warmup, interval, target ? "limited" : "unlimited (SIGINT to stop)");

    /* ── main read loop ───────────────────────────────────────────────── */
    while (g_running && (target == 0 || samples_done < target)) {

        ssize_t n = read(dev_fd, frame_buf, sizeof(frame_buf));

        /*
         * Capture receive_ts immediately after read() returns so that
         * time spent in the rest of this loop body is excluded.
         */
        struct timespec rts;
        clock_gettime(CLOCK_REALTIME, &rts);
        uint64_t receive_ts = (uint64_t)rts.tv_sec * 1000000000ULL
                            + (uint64_t)rts.tv_nsec;

        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EIO)   { LOG_INFO("EIO — module unloaded"); break; }
            LOG_ERROR("read: %s", strerror(errno));
            continue;
        }
        if (n == 0) continue;

        total_frames++;

        /* ── parse frame header ─────────────────────────────────────── */
        if (n < (ssize_t)sizeof(uint32_t)) {
            LOG_WARN("Short read: %zd bytes", n);
            continue;
        }

        uint32_t body_len;
        memcpy(&body_len, frame_buf, sizeof(body_len));

        /*
         * The body is a photon_encrypted_msg (variable length due to the
         * flexible array member).  Point directly into frame_buf to avoid
         * a copy.
         */
        if ((size_t)(sizeof(uint32_t) + body_len) > (size_t)n) {
            LOG_WARN("Truncated frame: header claims %u body bytes, read %zd",
                     body_len, n - (ssize_t)sizeof(uint32_t));
            continue;
        }

        const photon_encrypted_msg_t *enc =
            (const photon_encrypted_msg_t *)(frame_buf + sizeof(uint32_t));

        /* ── key derivation (cached per rotation) ───────────────────── */
        if (enc->rotation_num != cached_rotation) {
            if (derive_session_key(master_key, enc->rotation_num,
                                   session_key) != 0) {
                LOG_ERROR("Key derivation failed for rotation %llu",
                          (unsigned long long)enc->rotation_num);
                continue;
            }
            cached_rotation = enc->rotation_num;
            LOG_INFO("Derived session key for rotation %llu",
                     (unsigned long long)enc->rotation_num);
        }

        /* ── decrypt ────────────────────────────────────────────────── */
        photon_event_t event;
        if (decrypt_event(session_key, enc, &event) != 0) {
            auth_errors++;
            continue;
        }

        /* ── warmup discard ─────────────────────────────────────────── */
        if (total_frames <= warmup)
            continue;

        /* Ignore events where dispatch_ts was not stamped */
        if (event.dispatch_ts == 0)
            continue;

        /* ── compute latency ────────────────────────────────────────── */
        if (receive_ts < event.dispatch_ts) {
            /*
             * Negative latency should not happen with CLOCK_REALTIME on the
             * same machine, but guard against it in case of clock adjustment.
             */
            LOG_WARN("Negative latency on seq=%llu (clock jumped?)",
                     (unsigned long long)event.sequence_num);
            continue;
        }

        uint64_t latency_ns = receive_ts - event.dispatch_ts;

        stats_record(&stats, latency_ns);
        samples_done++;

        /* ── CSV ────────────────────────────────────────────────────── */
        if (csv)
            csv_append(csv, event.sequence_num,
                       event.dispatch_ts, receive_ts, latency_ns);

        /* ── periodic report ────────────────────────────────────────── */
        if (samples_done % interval == 0) {
            LOG_INFO("Sample %zu: seq=%-8llu latency=%.2f µs",
                     samples_done,
                     (unsigned long long)event.sequence_num,
                     (double)latency_ns / 1000.0);

            if (samples_done % (interval * 10) == 0)
                print_stats(&stats, total_frames, warmup, auth_errors);
        }
    }

    /* ── final report ─────────────────────────────────────────────────── */
    print_stats(&stats, total_frames, warmup, auth_errors);

    /* ── cleanup ──────────────────────────────────────────────────────── */
    if (csv) fclose(csv);
    close(dev_fd);
    free(stats.samples);
    memset(master_key,   0, sizeof(master_key));
    memset(session_key,  0, sizeof(session_key));

    LOG_INFO("Done.");
    return 0;
}