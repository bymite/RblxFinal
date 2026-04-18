#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/runtime.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "fishhook.h"

#define PROXY_HOST "roundhouse.proxy.rlwy.net"
#define PROXY_PORT 58298

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static uint32_t proxy_ip = 0;
static int hooking_active = 0;

#define MAX_HOST_CACHE 512
static struct { uint32_t ip; char host[256]; } host_cache[MAX_HOST_CACHE];
static int host_cache_count = 0;

static void cache_host(uint32_t ip, const char *host) {
    for (int i = 0; i < host_cache_count; i++)
        if (host_cache[i].ip == ip) return;
    if (host_cache_count >= MAX_HOST_CACHE) host_cache_count = 0;
    host_cache[host_cache_count].ip = ip;
    strncpy(host_cache[host_cache_count].host, host, 255);
    host_cache_count++;
}

static const char *lookup_host(uint32_t ip) {
    for (int i = 0; i < host_cache_count; i++)
        if (host_cache[i].ip == ip) return host_cache[i].host;
    return NULL;
}

static int hook_getaddrinfo(const char *hostname, const char *servname,
                             const struct addrinfo *hints, struct addrinfo **res) {
    int result = orig_getaddrinfo(hostname, servname, hints, res);
    if (result == 0 && hostname && res && *res)
        for (struct addrinfo *ai = *res; ai; ai = ai->ai_next)
            if (ai->ai_family == AF_INET)
                cache_host(((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr, hostname);
    return result;
}

#pragma mark - Banner

static void show_banner(NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = nil;
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]])
                for (UIWindow *w in ((UIWindowScene *)scene).windows)
                    if (w.isKeyWindow) { window = w; break; }
        }
        if (!window) return;
        UIView *banner = [[UIView alloc] initWithFrame:CGRectMake(0, 60, window.bounds.size.width, 50)];
        banner.backgroundColor = [UIColor colorWithRed:0.0 green:0.7 blue:0.3 alpha:0.95];
        banner.alpha = 0;
        UILabel *label = [[UILabel alloc] initWithFrame:CGRectInset(banner.bounds, 12, 6)];
        label.text = message;
        label.textColor = [UIColor whiteColor];
        label.font = [UIFont boldSystemFontOfSize:13];
        label.textAlignment = NSTextAlignmentCenter;
        [banner addSubview:label];
        [window addSubview:banner];
        [UIView animateWithDuration:0.4 animations:^{ banner.alpha = 1.0; }
                         completion:^(BOOL d) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                [UIView animateWithDuration:0.4 animations:^{ banner.alpha = 0; }
                                 completion:^(BOOL d2) { [banner removeFromSuperview]; }];
            });
        }];
    });
}

#pragma mark - Proxy

static void resolve_proxy() {
    if (proxy_ip != 0) return;
    hooking_active = 1;
    struct hostent *he = gethostbyname(PROXY_HOST);
    hooking_active = 0;
    if (he && he->h_addrtype == AF_INET)
        memcpy(&proxy_ip, he->h_addr_list[0], 4);
}

static int wait_for_connect(int fd, int secs) {
    fd_set w; FD_ZERO(&w); FD_SET(fd, &w);
    struct timeval tv = {secs, 0};
    if (select(fd+1, NULL, &w, NULL, &tv) <= 0) return -1;
    int err = 0; socklen_t l = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
    return err == 0 ? 0 : -1;
}

static int socks5_handshake(int fd, const char *host, int port) {
    uint8_t g[] = {0x05, 0x01, 0x00};
    if (send(fd, g, 3, MSG_NOSIGNAL) < 0) return -1;
    uint8_t r[2]; if (recv(fd, r, 2, 0) < 2 || r[1] != 0x00) return -1;

    size_t hl = strlen(host);
    uint8_t req[7+256];
    req[0]=0x05; req[1]=0x01; req[2]=0x00; req[3]=0x03;
    req[4]=(uint8_t)hl;
    memcpy(req+5, host, hl);
    req[5+hl]=(port>>8)&0xFF; req[6+hl]=port&0xFF;
    if (send(fd, req, 7+hl, MSG_NOSIGNAL) < 0) return -1;

    uint8_t sr[10]; if (recv(fd, sr, 10, 0) < 2 || sr[1] != 0x00) return -1;
    return 0;
}

#pragma mark - Hook

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr || hooking_active)
        return orig_connect(sockfd, addr, addrlen);
    if (addr->sa_family != AF_INET)
        return orig_connect(sockfd, addr, addrlen);

    struct sockaddr_in *s = (struct sockaddr_in *)addr;
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &s->sin_addr, dest_ip, sizeof(dest_ip));
    int dest_port = ntohs(s->sin_port);

    if (strncmp(dest_ip, "127.", 4) == 0)
        return orig_connect(sockfd, addr, addrlen);

    resolve_proxy();
    if (proxy_ip == 0 || s->sin_addr.s_addr == proxy_ip)
        return orig_connect(sockfd, addr, addrlen);

    const char *hostname = lookup_host(s->sin_addr.s_addr);
    const char *dest = hostname ? hostname : dest_ip;

    // Save flags and force blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

    // Connect to proxy
    struct sockaddr_in px;
    memset(&px, 0, sizeof(px));
    px.sin_family = AF_INET;
    memcpy(&px.sin_addr, &proxy_ip, 4);
    px.sin_port = htons(PROXY_PORT);

    hooking_active = 1;
    int r = orig_connect(sockfd, (struct sockaddr *)&px, sizeof(px));
    hooking_active = 0;

    if (r != 0 && errno == EINPROGRESS)
        r = wait_for_connect(sockfd, 10);

    if (r != 0) {
        fcntl(sockfd, F_SETFL, flags);
        return orig_connect(sockfd, addr, addrlen);
    }

    // Do SOCKS5 handshake
    r = socks5_handshake(sockfd, dest, dest_port);

    // Restore original flags
    fcntl(sockfd, F_SETFL, flags);

    // Return 0 = connected. Caller handles it correctly whether blocking or not.
    return r;
}

// Also hook NSURLSession
static NSURLSessionConfiguration *(*orig_defaultConfig)(id, SEL);
static NSURLSessionConfiguration *hook_defaultConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *c = orig_defaultConfig(self, _cmd);
    c.connectionProxyDictionary = @{
        @"SOCKSEnable": @1,
        @"SOCKSProxy": @PROXY_HOST,
        @"SOCKSPort": @PROXY_PORT,
    };
    return c;
}

#pragma mark - Init

__attribute__((constructor))
static void init() {
    rebind_symbols((struct rebinding[2]){
        {"connect",     hook_connect,     (void **)&orig_connect},
        {"getaddrinfo", hook_getaddrinfo, (void **)&orig_getaddrinfo},
    }, 2);

    Method m = class_getClassMethod([NSURLSessionConfiguration class],
                                    @selector(defaultSessionConfiguration));
    orig_defaultConfig = (void *)method_getImplementation(m);
    method_setImplementation(m, (IMP)hook_defaultConfig);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2*NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        show_banner(@"🟢 Proxy Active → roundhouse.proxy.rlwy.net:58298");
    });
}
