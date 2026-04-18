#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "fishhook.h"

#define PROXY_HOST "roundhouse.proxy.rlwy.net"
#define PROXY_PORT 58298

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);

static int socks5_handshake(int sockfd, const char *dest_ip, int dest_port) {
    // SOCKS5 greeting: version 5, 1 auth method, no auth
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    send(sockfd, greeting, sizeof(greeting), 0);

    // Read server choice
    uint8_t resp[2] = {0};
    recv(sockfd, resp, 2, 0);
    if (resp[0] != 0x05 || resp[1] != 0x00) return -1;

    // SOCKS5 connect request
    struct in_addr ipv4;
    if (inet_pton(AF_INET, dest_ip, &ipv4) == 1) {
        // IPv4
        uint8_t req[10];
        req[0] = 0x05; // version
        req[1] = 0x01; // connect
        req[2] = 0x00; // reserved
        req[3] = 0x01; // IPv4
        memcpy(req + 4, &ipv4, 4);
        req[8] = (dest_port >> 8) & 0xFF;
        req[9] = dest_port & 0xFF;
        send(sockfd, req, 10, 0);
    } else {
        // Try as hostname
        size_t hlen = strlen(dest_ip);
        uint8_t req[7 + hlen];
        req[0] = 0x05;
        req[1] = 0x01;
        req[2] = 0x00;
        req[3] = 0x03; // domain
        req[4] = (uint8_t)hlen;
        memcpy(req + 5, dest_ip, hlen);
        req[5 + hlen] = (dest_port >> 8) & 0xFF;
        req[6 + hlen] = dest_port & 0xFF;
        send(sockfd, req, 7 + hlen, 0);
    }

    // Read response
    uint8_t sresp[10] = {0};
    recv(sockfd, sresp, 10, 0);
    if (sresp[0] != 0x05 || sresp[1] != 0x00) return -1;

    return 0;
}

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr) return orig_connect(sockfd, addr, addrlen);

    // Only hook TCP
    int type = 0;
    socklen_t typeLen = sizeof(type);
    getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &typeLen);
    if (type != SOCK_STREAM) return orig_connect(sockfd, addr, addrlen);
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
        return orig_connect(sockfd, addr, addrlen);

    // Get destination
    char dest_ip[INET6_ADDRSTRLEN] = {0};
    int dest_port = 0;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &s->sin_addr, dest_ip, sizeof(dest_ip));
        dest_port = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &s->sin6_addr, dest_ip, sizeof(dest_ip));
        dest_port = ntohs(s->sin6_port);
    }

    // Skip loopback
    if (strncmp(dest_ip, "127.", 4) == 0 || strcmp(dest_ip, "::1") == 0)
        return orig_connect(sockfd, addr, addrlen);

    // Resolve proxy
    struct hostent *he = gethostbyname(PROXY_HOST);
    if (!he) return orig_connect(sockfd, addr, addrlen);

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    memcpy(&proxy_addr.sin_addr, he->h_addr_list[0], he->h_length);
    proxy_addr.sin_port = htons(PROXY_PORT);

    // Set blocking for handshake
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

    // Connect to SOCKS5 proxy
    int result = orig_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    if (result != 0) {
        fcntl(sockfd, F_SETFL, flags);
        return orig_connect(sockfd, addr, addrlen);
    }

    // Do SOCKS5 handshake
    result = socks5_handshake(sockfd, dest_ip, dest_port);

    // Restore flags
    fcntl(sockfd, F_SETFL, flags);

    return result;
}

// NSURLSession fallback
static NSURLSessionConfiguration *(*orig_defaultConfig)(id, SEL);
static NSURLSessionConfiguration *hook_defaultConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *config = orig_defaultConfig(self, _cmd);
    config.connectionProxyDictionary = @{
        @"SOCKSEnable": @1,
        @"SOCKSProxy":  @PROXY_HOST,
        @"SOCKSPort":   @PROXY_PORT,
    };
    return config;
}

__attribute__((constructor))
static void init() {
    rebind_symbols((struct rebinding[1]){
        {"connect", hook_connect, (void **)&orig_connect}
    }, 1);

    Method m = class_getClassMethod([NSURLSessionConfiguration class],
                                    @selector(defaultSessionConfiguration));
    orig_defaultConfig = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)hook_defaultConfig);
}
