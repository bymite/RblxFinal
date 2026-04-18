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

#define PROXY_HOST "mainline.proxy.rlwy.net"
#define PROXY_PORT 55396

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr) return orig_connect(sockfd, addr, addrlen);

    // Only hook IPv4/IPv6 TCP
    int type = 0;
    socklen_t typeLen = sizeof(type);
    getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &typeLen);
    if (type != SOCK_STREAM) return orig_connect(sockfd, addr, addrlen);
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
        return orig_connect(sockfd, addr, addrlen);

    // Get destination IP and port
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

    // Save + set blocking mode for handshake
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

    // Connect to proxy
    int result = orig_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    if (result != 0) {
        fcntl(sockfd, F_SETFL, flags);
        return orig_connect(sockfd, addr, addrlen);
    }

    // Send CONNECT
    char req[512];
    snprintf(req, sizeof(req),
        "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
        dest_ip, dest_port, dest_ip, dest_port);
    send(sockfd, req, strlen(req), 0);

    // Read response
    char resp[512] = {0};
    recv(sockfd, resp, sizeof(resp) - 1, 0);

    // Restore original flags
    fcntl(sockfd, F_SETFL, flags);

    if (strstr(resp, "200") == NULL) return -1;
    return 0;
}

// Also hook NSURLSession as a fallback for HTTP traffic
static NSURLSessionConfiguration *(*orig_defaultConfig)(id, SEL);
static NSURLSessionConfiguration *hook_defaultConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *config = orig_defaultConfig(self, _cmd);
    config.connectionProxyDictionary = @{
        @"HTTPEnable": @1, @"HTTPProxy": @PROXY_HOST, @"HTTPPort": @PROXY_PORT,
        @"HTTPSEnable": @1, @"HTTPSProxy": @PROXY_HOST, @"HTTPSPort": @PROXY_PORT,
    };
    return config;
}

__attribute__((constructor))
static void init() {
    // Hook low-level connect()
    rebind_symbols((struct rebinding[1]){
        {"connect", hook_connect, (void **)&orig_connect}
    }, 1);

    // Hook NSURLSession
    Method m = class_getClassMethod([NSURLSessionConfiguration class],
                                    @selector(defaultSessionConfiguration));
    orig_defaultConfig = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)hook_defaultConfig);
}
