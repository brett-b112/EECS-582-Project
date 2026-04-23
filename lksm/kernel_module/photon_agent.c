/*
 * photon_agent.c — Photon Ring Userspace Log Agent
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o photon_agent photon_agent.c -lssl -lcrypto
 *
 * Responsibilities:
 *   1. Connect to the remote Photon Ring server over TLS 1.3 (mutual auth).
 *   2. Receive the 32-byte master key from the server.
 *   3. Hand the master key to the kernel module via ioctl(PHOTON_IOC_SET_KEY).
 *   4. Read length-prefixed encrypted frames from /dev/photon_ring in a loop.
 *   5. Forward each frame (still encrypted) to the server over the TLS channel.
 *   6. On SIGTERM / SIGINT: drain the device, close gracefully.
 *
 * The agent intentionally does NOT decrypt frames — it is just a secure relay.
 * All decryption happens on the trusted remote server.
 *
 * Wire protocol (must match photon_server.py):
 *   agent → server  : 4-byte magic  "PROG"
 *   server → agent  : 1-byte 0x01 (KEY_OFFER) + 32-byte master key
 *   agent → server  : 1-byte 0x02 (KEY_ACK)
 *   agent → server  : [u32 body_len LE][body...] frames, continuously
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>

/* OpenSSL */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ─────────────────────────────────────────────────── kernel ioctl defs ──── */
/* Mirrors cdev_ch.h exactly (kept here so we don't need the kernel headers) */
#define PHOTON_KEY_SIZE          32
#define PHOTON_RING_DEV          "/dev/photon_ring"
#define PHOTON_RING_IOC_MAGIC    0xBE
#define PHOTON_IOC_SET_KEY       _IOW(PHOTON_RING_IOC_MAGIC, 1, uint8_t[32])

/* ─────────────────────────────────────────────────── protocol constants ─── */
static const uint8_t MAGIC[4]   = { 0x50, 0x52, 0x4f, 0x47 };  /* "PROG" */
#define MSG_KEY_OFFER  0x01
#define MSG_KEY_ACK    0x02

/* Maximum body size must cover the largest possible photon_encrypted_msg:
 *   fixed header: u64 rotation + u8[12] iv + u16 enc_len + u8[16] tag = 38
 *   + sizeof(photon_event) = 538
 *   = 576 bytes body; 580 bytes total with the u32 length prefix.
 * We use 8 KB to be future-proof.
 */
#define MAX_FRAME_BYTES   8192

/* ─────────────────────────────────────────────────── globals ────────────── */
static volatile sig_atomic_t g_running = 1;
static int    g_dev_fd  = -1;
static SSL   *g_ssl     = NULL;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/* ─────────────────────────────────────────────────── helpers ────────────── */

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

static void print_openssl_error(const char *ctx) {
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        LOG_ERROR("%s: %s", ctx, buf);
    }
}

/*
 * recv_all - read exactly `n` bytes from an SSL connection.
 * Returns 0 on success, -1 on EOF/error.
 */
static int ssl_recv_all(SSL *ssl, void *buf, size_t n) {
    uint8_t *p   = (uint8_t *)buf;
    size_t  done = 0;
    while (done < n) {
        int r = SSL_read(ssl, p + done, (int)(n - done));
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            if (err == SSL_ERROR_ZERO_RETURN) {
                LOG_INFO("Server closed the connection");
            } else {
                print_openssl_error("SSL_read");
            }
            return -1;
        }
        done += (size_t)r;
    }
    return 0;
}

/*
 * send_all - write exactly `n` bytes to an SSL connection.
 */
static int ssl_send_all(SSL *ssl, const void *buf, size_t n) {
    const uint8_t *p   = (const uint8_t *)buf;
    size_t         done = 0;
    while (done < n) {
        int r = SSL_write(ssl, p + done, (int)(n - done));
        if (r <= 0) {
            print_openssl_error("SSL_write");
            return -1;
        }
        done += (size_t)r;
    }
    return 0;
}

/* ─────────────────────────────────────────────────── TLS setup ──────────── */

static SSL_CTX *build_ssl_ctx(const char *cert, const char *key,
                               const char *ca) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { print_openssl_error("SSL_CTX_new"); return NULL; }

    /* Require TLS 1.3 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    /* Load client cert + key (mutual TLS) */
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
        print_openssl_error("load cert"); SSL_CTX_free(ctx); return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        print_openssl_error("load key"); SSL_CTX_free(ctx); return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        print_openssl_error("check key"); SSL_CTX_free(ctx); return NULL;
    }

    /* Verify server cert against CA */
    if (SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
        print_openssl_error("load CA"); SSL_CTX_free(ctx); return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
    return ctx;
}

static SSL *connect_tls(SSL_CTX *ctx, const char *host, const char *port_str,
                         int *out_fd) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        LOG_ERROR("getaddrinfo(%s:%s): %s", host, port_str, gai_strerror(rc));
        return NULL;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        LOG_ERROR("TCP connect to %s:%s failed: %s", host, port_str, strerror(errno));
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { print_openssl_error("SSL_new"); close(fd); return NULL; }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);   /* SNI */

    if (SSL_connect(ssl) != 1) {
        print_openssl_error("SSL_connect");
        SSL_free(ssl); close(fd);
        return NULL;
    }

    LOG_INFO("TLS 1.3 connection established to %s:%s", host, port_str);
    *out_fd = fd;
    return ssl;
}

/* ─────────────────────────────────────────────────── key exchange ───────── */

/*
 * do_key_exchange - run the handshake protocol and receive the master key.
 *
 *   1. Send 4-byte magic.
 *   2. Wait for KEY_OFFER (1 byte) + 32-byte key.
 *   3. Send KEY_ACK.
 *
 * Returns 0 on success, -1 on failure.
 */
static int do_key_exchange(SSL *ssl, uint8_t *key_out) {
    /* Send magic */
    if (ssl_send_all(ssl, MAGIC, sizeof(MAGIC)) != 0) {
        LOG_ERROR("Failed to send magic");
        return -1;
    }
    LOG_INFO("Magic sent, waiting for key offer...");

    /* Receive KEY_OFFER + key */
    uint8_t offer_byte;
    if (ssl_recv_all(ssl, &offer_byte, 1) != 0 || offer_byte != MSG_KEY_OFFER) {
        LOG_ERROR("Expected KEY_OFFER (0x01), got 0x%02x", offer_byte);
        return -1;
    }
    if (ssl_recv_all(ssl, key_out, PHOTON_KEY_SIZE) != 0) {
        LOG_ERROR("Failed to receive master key");
        return -1;
    }
    LOG_INFO("Master key received (%d bytes)", PHOTON_KEY_SIZE);

    /* Send KEY_ACK */
    uint8_t ack = MSG_KEY_ACK;
    if (ssl_send_all(ssl, &ack, 1) != 0) {
        LOG_ERROR("Failed to send KEY_ACK");
        return -1;
    }
    LOG_INFO("KEY_ACK sent — key exchange complete");
    return 0;
}

/* ─────────────────────────────────────────────────── kernel key injection ─ */

/*
 * set_kernel_key - pass the master key to the kernel module via ioctl.
 *
 * Opens /dev/photon_ring, issues PHOTON_IOC_SET_KEY, closes the fd.
 * The device fd used for reading is opened separately afterward.
 *
 * Returns 0 on success, -1 on failure.
 */
static int set_kernel_key(const uint8_t *key) {
    int fd = open(PHOTON_RING_DEV, O_RDWR);
    if (fd < 0) {
        LOG_ERROR("open(%s): %s", PHOTON_RING_DEV, strerror(errno));
        return -1;
    }

    /* ioctl expects a pointer to 32-byte buffer */
    if (ioctl(fd, PHOTON_IOC_SET_KEY, key) < 0) {
        if (errno == EEXIST) {
            LOG_WARN("Kernel already has a key set (EEXIST) — continuing");
        } else {
            LOG_ERROR("ioctl(PHOTON_IOC_SET_KEY): %s", strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        LOG_INFO("Master key delivered to kernel module successfully");
    }

    close(fd);
    return 0;
}

/* ─────────────────────────────────────────────────── frame relay loop ────── */

/*
 * run_relay - read frames from /dev/photon_ring and forward to server.
 *
 * Each iteration:
 *   1. read() blocks until a frame is available (kernel wakes us).
 *   2. The kernel writes: [u32 body_len][body...] in one read() call.
 *   3. We forward the same byte sequence verbatim to the server.
 *
 * The agent does NOT inspect or decrypt frames — that's the server's job.
 */
static int run_relay(SSL *ssl) {
    static uint8_t frame_buf[MAX_FRAME_BYTES];
    uint64_t total_frames = 0;
    uint64_t total_bytes  = 0;
    uint64_t total_errors = 0;

    /* Open device for reading */
    g_dev_fd = open(PHOTON_RING_DEV, O_RDONLY);
    if (g_dev_fd < 0) {
        LOG_ERROR("open(%s) for read: %s", PHOTON_RING_DEV, strerror(errno));
        return -1;
    }
    LOG_INFO("Opened %s for reading — relay loop starting", PHOTON_RING_DEV);

    while (g_running) {
        /*
         * read() from the cdev blocks (interruptible) until a frame arrives.
         * The kernel's photon_cdev_read() returns the full frame in one call:
         *   bytes 0-3:  u32 body_len (LE)
         *   bytes 4+:   encrypted body
         */
        ssize_t n = read(g_dev_fd, frame_buf, sizeof(frame_buf));
        if (n < 0) {
            if (errno == EINTR) continue;          /* signal, re-check g_running */
            if (errno == EIO)   {                  /* device shutting down */
                LOG_INFO("Device returned EIO — module unloaded?");
                break;
            }
            LOG_ERROR("read(%s): %s", PHOTON_RING_DEV, strerror(errno));
            total_errors++;
            continue;
        }
        if (n == 0) continue;

        if (n < (ssize_t)sizeof(uint32_t)) {
            LOG_WARN("Short read: %zd bytes, expected at least 4", n);
            total_errors++;
            continue;
        }

        /* Sanity-check: frame_buf[0..3] should equal n - 4 */
        uint32_t body_len;
        memcpy(&body_len, frame_buf, sizeof(body_len));
        /* body_len is LE; on any plausible arch this is fine */
        if ((ssize_t)(body_len + sizeof(uint32_t)) != n) {
            LOG_WARN("Frame length mismatch: header says %u body, read %zd total",
                     body_len, n);
            /* forward anyway — server will reject if bad */
        }

        /* Forward the entire frame verbatim (including the u32 length prefix) */
        if (ssl_send_all(ssl, frame_buf, (size_t)n) != 0) {
            LOG_ERROR("Failed to forward frame to server");
            total_errors++;
            break;
        }

        total_frames++;
        total_bytes += (uint64_t)n;

        if (total_frames % 100 == 0) {
            LOG_INFO("Relayed %lu frames (%lu bytes, %lu errors)",
                     (unsigned long)total_frames,
                     (unsigned long)total_bytes,
                     (unsigned long)total_errors);
        }
    }

    LOG_INFO("Relay loop ended — total: %lu frames, %lu bytes, %lu errors",
             (unsigned long)total_frames,
             (unsigned long)total_bytes,
             (unsigned long)total_errors);

    close(g_dev_fd);
    g_dev_fd = -1;
    return 0;
}

/* ─────────────────────────────────────────────────── reconnect logic ────── */

/*
 * connect_and_run - establish TLS, exchange key, inject into kernel, relay.
 *
 * Returns 0 on clean shutdown, -1 on unrecoverable error.
 */
static int connect_and_run(SSL_CTX *ctx,
                            const char *host, const char *port,
                            int inject_key) {
    int tcp_fd = -1;
    SSL *ssl   = connect_tls(ctx, host, port, &tcp_fd);
    if (!ssl) return -1;
    g_ssl = ssl;

    uint8_t master_key[PHOTON_KEY_SIZE];
    memset(master_key, 0, sizeof(master_key));

    if (do_key_exchange(ssl, master_key) != 0) {
        goto fail;
    }

    if (inject_key) {
        if (set_kernel_key(master_key) != 0) {
            goto fail_wipe;
        }
    }

    /* Wipe local copy of master key — kernel has it now */
    memset(master_key, 0, sizeof(master_key));

    run_relay(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(tcp_fd);
    g_ssl = NULL;
    return 0;

fail_wipe:
    memset(master_key, 0, sizeof(master_key));
fail:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(tcp_fd);
    g_ssl = NULL;
    return -1;
}

/* ─────────────────────────────────────────────────── main ───────────────── */

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  --host HOST       Server hostname/IP  (default: 127.0.0.1)\n"
        "  --port PORT       Server port         (default: 9443)\n"
        "  --cert FILE       Client cert PEM     (default: certs/client.crt)\n"
        "  --key  FILE       Client key PEM      (default: certs/client.key)\n"
        "  --ca   FILE       CA cert PEM         (default: certs/ca.crt)\n"
        "  --no-inject       Don't inject key into kernel (testing mode)\n"
        "  --retry-delay S   Seconds between reconnect attempts (default: 5)\n"
        "  --help            Show this help\n",
        argv0
    );
}

int main(int argc, char *argv[]) {
    const char *host        = "127.0.0.1";
    const char *port        = "9443";
    const char *cert        = "certs/client.crt";
    const char *key_file    = "certs/client.key";
    const char *ca          = "certs/ca.crt";
    int         inject_key  = 1;
    int         retry_delay = 5;

    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--host")        && i+1 < argc) host        = argv[++i];
        else if (!strcmp(argv[i], "--port")        && i+1 < argc) port        = argv[++i];
        else if (!strcmp(argv[i], "--cert")        && i+1 < argc) cert        = argv[++i];
        else if (!strcmp(argv[i], "--key")         && i+1 < argc) key_file    = argv[++i];
        else if (!strcmp(argv[i], "--ca")          && i+1 < argc) ca          = argv[++i];
        else if (!strcmp(argv[i], "--retry-delay") && i+1 < argc) retry_delay = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--no-inject"))                  inject_key  = 0;
        else if (!strcmp(argv[i], "--help"))  { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    /* Signal handlers for graceful shutdown */
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* OpenSSL init (no-op in OpenSSL 1.1+, good practice) */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = build_ssl_ctx(cert, key_file, ca);
    if (!ctx) {
        LOG_ERROR("Failed to build TLS context");
        return 1;
    }

    LOG_INFO("Photon Ring agent starting (server=%s:%s)", host, port);

    /* Reconnect loop */
    while (g_running) {
        int rc = connect_and_run(ctx, host, port, inject_key);
        if (!g_running) break;
        if (rc != 0) {
            LOG_WARN("Connection failed, retrying in %d seconds...", retry_delay);
        } else {
            LOG_INFO("Connection closed, reconnecting in %d seconds...", retry_delay);
        }
        sleep((unsigned)retry_delay);
    }

    LOG_INFO("Agent shutting down cleanly");
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}