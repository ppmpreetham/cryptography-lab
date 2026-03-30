#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "elgamal.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

/* ─── Wire Protocol ──────────────────────────────────────────────────────── */
/*
 * Every frame on the wire:
 *   [ uint32_t payload_len ] [ payload bytes ]
 *
 * The payload is a serialised SignedMessage (fixed size for simplicity;
 * a production system would use a proper serialisation format).
 */

#define FRAME_HEADER_LEN (sizeof(uint32_t))

/* ─── Send / Recv helpers ────────────────────────────────────────────────── */

/**
 * Send exactly `len` bytes from buf over fd.
 * Returns 0 on success, -1 on error.
 */
static inline int send_all(int fd, const void *buf, size_t len) {
    const char *ptr = (const char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t sent = send(fd, ptr, remaining, 0);
        if (sent <= 0) return -1;
        ptr       += sent;
        remaining -= (size_t)sent;
    }
    return 0;
}

/**
 * Receive exactly `len` bytes into buf from fd.
 * Returns 0 on success, -1 on error / EOF.
 */
static inline int recv_all(int fd, void *buf, size_t len) {
    char *ptr = (char *)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t got = recv(fd, ptr, remaining, 0);
        if (got <= 0) return -1;
        ptr       += got;
        remaining -= (size_t)got;
    }
    return 0;
}

/* ─── Frame-level send / recv ────────────────────────────────────────────── */

static inline int send_signed_message(int fd, const SignedMessage *sm) {
    uint32_t len = htonl((uint32_t)sizeof(SignedMessage));
    if (send_all(fd, &len, FRAME_HEADER_LEN) < 0) return -1;
    return send_all(fd, sm, sizeof(SignedMessage));
}

static inline int recv_signed_message(int fd, SignedMessage *sm) {
    uint32_t len_net;
    if (recv_all(fd, &len_net, FRAME_HEADER_LEN) < 0) return -1;
    uint32_t len = ntohl(len_net);
    if (len != sizeof(SignedMessage)) return -1; /* unexpected payload size */
    return recv_all(fd, sm, sizeof(SignedMessage));
}

/* ─── Socket helpers ─────────────────────────────────────────────────────── */

/**
 * Create and bind a TCP listening socket on the given port.
 * Returns the fd or -1 on error.
 */
static inline int create_server_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons((uint16_t)port),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    if (listen(fd, 5) < 0) { close(fd); return -1; }
    return fd;
}

/**
 * Connect to host:port as a TCP client.
 * Returns the fd or -1 on error.
 */
static inline int create_client_socket(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)port)
    };
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd); return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    return fd;
}

#endif /* PROTOCOL_H */
