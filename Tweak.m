#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include "fishhook.h"

// IMPORTANT: Match these to your Railway Public URL and Port
#define PROXY_HOST "roundhouse.proxy.rlwy.net"
#define PROXY_PORT 58298

static int (*orig_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*orig_recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static int (*orig_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
static int (*orig_connect)(int, const struct sockaddr *, socklen_t);

static int tunnel_fd = -1; 
static int game_fd = -1;

// Function to establish the TCP tunnel if it doesn't exist
static void ensure_tunnel() {
    if (tunnel_fd != -1) return;
    
    struct sockaddr_in addr;
    tunnel_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PROXY_PORT);
    
    struct hostent *he = gethostbyname(PROXY_HOST);
    if (!he) return;
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    if (orig_connect(tunnel_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(tunnel_fd);
        tunnel_fd = -1;
    }
}

static ssize_t hook_sendto(int s, const void *buf, size_t len, int f, const struct sockaddr *d, socklen_t al) {
    // Detect Roblox Gameplay UDP packets
    int type; socklen_t slen = sizeof(type);
    getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &slen);
    
    if (type == SOCK_DGRAM) {
        game_fd = s;
        ensure_tunnel();
        if (tunnel_fd != -1) {
            // Send length header (2 bytes) + packet data over TCP
            uint16_t plen = htons(len);
            send(tunnel_fd, &plen, 2, 0);
            return send(tunnel_fd, buf, len, 0);
        }
    }
    return orig_sendto(s, buf, len, f, d, al);
}

static ssize_t hook_recvfrom(int s, void *buf, size_t len, int f, struct sockaddr *src, socklen_t *al) {
    if (s == game_fd && tunnel_fd != -1) {
        uint16_t plen;
        if (recv(tunnel_fd, &plen, 2, MSG_WAITALL) <= 0) return -1;
        return recv(tunnel_fd, buf, ntohs(plen), MSG_WAITALL);
    }
    return orig_recvfrom(s, buf, len, f, src, al);
}

static int hook_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *t) {
    if (r && game_fd != -1 && FD_ISSET(game_fd, r)) {
        FD_CLR(game_fd, r);
        FD_SET(tunnel_fd, r);
        int res = orig_select(n > tunnel_fd ? n : tunnel_fd + 1, r, w, e, t);
        if (FD_ISSET(tunnel_fd, r)) {
            FD_CLR(tunnel_fd, r);
            FD_SET(game_fd, r);
        }
        return res;
    }
    return orig_select(n, r, w, e, t);
}

__attribute__((constructor))
static void init() {
    rebind_symbols((struct rebinding[4]){
        {"sendto", hook_sendto, (void **)&orig_sendto},
        {"recvfrom", hook_recvfrom, (void **)&orig_recvfrom},
        {"select", hook_select, (void **)&orig_select},
        {"connect", hook_connect, (void **)&orig_connect}
    }, 4);
}
