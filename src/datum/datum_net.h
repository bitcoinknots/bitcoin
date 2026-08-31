/* Copyright (c) 2026 The Bitcoin Purity developers
 * Distributed under the MIT software license. */
#ifndef BITCOINPURITY_DATUM_NET_H
#define BITCOINPURITY_DATUM_NET_H

#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
typedef SOCKET datum_socket_t;
typedef WSAPOLLFD datum_pollfd;
typedef int datum_socklen_t;
#define DATUM_INVALID_SOCKET INVALID_SOCKET
#define DATUM_POLLIN POLLRDNORM
#define DATUM_POLL_READY (POLLRDNORM | POLLERR | POLLHUP | POLLNVAL)
#define DATUM_MSG_DONTWAIT 0
static inline int datum_poll(datum_pollfd *fds, unsigned long count, int timeout) { return WSAPoll(fds, count, timeout); }
static inline int datum_socket_close(datum_socket_t socket) { return closesocket(socket); }
static inline int datum_socket_set_nonblocking(datum_socket_t socket) { u_long enabled = 1; return ioctlsocket(socket, FIONBIO, &enabled); }
static inline int datum_socket_would_block(void) { const int error = WSAGetLastError(); return error == WSAEWOULDBLOCK; }
static inline int datum_net_init(void) { WSADATA data; return WSAStartup(MAKEWORD(2, 2), &data); }
static inline void datum_net_cleanup(void) { WSACleanup(); }
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef int datum_socket_t;
typedef struct pollfd datum_pollfd;
typedef socklen_t datum_socklen_t;
#define DATUM_INVALID_SOCKET (-1)
#define DATUM_POLLIN POLLIN
#define DATUM_POLL_READY (POLLIN | POLLERR | POLLHUP | POLLNVAL)
#define DATUM_MSG_DONTWAIT MSG_DONTWAIT
static inline int datum_poll(datum_pollfd *fds, unsigned long count, int timeout) { return poll(fds, count, timeout); }
static inline int datum_socket_close(datum_socket_t socket) { return close(socket); }
static inline int datum_socket_set_nonblocking(datum_socket_t socket)
{
    const int flags = fcntl(socket, F_GETFL);
    return flags < 0 ? -1 : fcntl(socket, F_SETFL, flags | O_NONBLOCK);
}
static inline int datum_socket_would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK; }
static inline int datum_net_init(void) { return 0; }
static inline void datum_net_cleanup(void) {}
#endif

#endif
