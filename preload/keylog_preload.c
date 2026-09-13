/*
 * keylog_preload.c -- LD_PRELOAD interposer for OpenSSL's SSL_CTX_new /
 * SSL_CTX_new_ex. Registers a keylog callback (SSL_CTX_set_keylog_callback)
 * on every context the app creates, then ships each already NSS-formatted
 * line, verbatim, over a Unix domain socket to the sidecar. See
 * .specs/features/02-uprobe-keylog/design.md (AD-010).
 *
 * Socket path comes from GOEBPF_PRELOAD_SOCKET (read once, cached). If
 * unset, the interposer still registers the callback (SSL_CTX_new keeps
 * working normally) but never attempts a socket connection -- a true no-op.
 *
 * Never blocks or crashes the app: connect/write failures retry briefly
 * with a short backoff, then the line is silently dropped and the socket
 * is reconnected lazily on the next line.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

typedef SSL_CTX *(*ssl_ctx_new_fn)(const SSL_METHOD *method);
typedef SSL_CTX *(*ssl_ctx_new_ex_fn)(OSSL_LIB_CTX *libctx, const char *propq, const SSL_METHOD *meth);

#define KEYLOG_MAX_SEND_ATTEMPTS 3
#define KEYLOG_RETRY_DELAY_NS (20L * 1000L * 1000L) /* 20ms */

static pthread_mutex_t g_sock_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_sock_fd = -1;
static int g_socket_path_loaded = 0;
static const char *g_socket_path = NULL; /* NULL/empty: no-op, never connect */

/* load_socket_path_once reads GOEBPF_PRELOAD_SOCKET exactly once. */
static void load_socket_path_once(void) {
    if (g_socket_path_loaded) {
        return;
    }
    g_socket_path = getenv("GOEBPF_PRELOAD_SOCKET");
    g_socket_path_loaded = 1;
}

/* connect_locked (re)connects g_sock_fd; caller must hold g_sock_mu. */
static int connect_locked(void) {
    if (g_sock_fd >= 0) {
        return 0;
    }
    if (g_socket_path == NULL || g_socket_path[0] == '\0') {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_socket_path, sizeof(addr.sun_path) - 1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    g_sock_fd = fd;
    return 0;
}

/* send_line_locked writes buf (len bytes) to the cached socket, retrying a
 * bounded number of times with a short backoff on connect/write failure,
 * then giving up silently. Caller must hold g_sock_mu. */
static void send_line_locked(const char *buf, size_t len) {
    for (int attempt = 0; attempt < KEYLOG_MAX_SEND_ATTEMPTS; attempt++) {
        if (connect_locked() != 0) {
            struct timespec ts = {0, KEYLOG_RETRY_DELAY_NS};
            nanosleep(&ts, NULL);
            continue;
        }
        ssize_t n = write(g_sock_fd, buf, len);
        if (n == (ssize_t)len) {
            return;
        }
        /* Partial write or error: the connection is broken -- drop it and
         * reconnect fresh on the next attempt/line, never mid-stream. */
        close(g_sock_fd);
        g_sock_fd = -1;
        struct timespec ts = {0, KEYLOG_RETRY_DELAY_NS};
        nanosleep(&ts, NULL);
    }
    /* Bounded retries exhausted: drop this line silently. */
}

/* keylog_cb is OpenSSL's keylog callback: line is already NSS-formatted and
 * forwarded verbatim, newline-terminated, with no reformatting. */
static void keylog_cb(const SSL *ssl, const char *line) {
    (void)ssl;
    load_socket_path_once();
    if (g_socket_path == NULL || g_socket_path[0] == '\0') {
        return;
    }

    size_t linelen = strlen(line);
    char *buf = malloc(linelen + 1);
    if (buf == NULL) {
        return;
    }
    memcpy(buf, line, linelen);
    buf[linelen] = '\n';

    pthread_mutex_lock(&g_sock_mu);
    send_line_locked(buf, linelen + 1);
    pthread_mutex_unlock(&g_sock_mu);

    free(buf);
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) {
    static ssl_ctx_new_fn real_fn = NULL;
    if (real_fn == NULL) {
        real_fn = (ssl_ctx_new_fn)dlsym(RTLD_NEXT, "SSL_CTX_new");
    }
    SSL_CTX *ctx = real_fn != NULL ? real_fn(method) : NULL;
    if (ctx != NULL) {
        SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    }
    return ctx;
}

SSL_CTX *SSL_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq, const SSL_METHOD *meth) {
    static ssl_ctx_new_ex_fn real_fn = NULL;
    if (real_fn == NULL) {
        real_fn = (ssl_ctx_new_ex_fn)dlsym(RTLD_NEXT, "SSL_CTX_new_ex");
    }
    SSL_CTX *ctx = real_fn != NULL ? real_fn(libctx, propq, meth) : NULL;
    if (ctx != NULL) {
        SSL_CTX_set_keylog_callback(ctx, keylog_cb);
    }
    return ctx;
}
