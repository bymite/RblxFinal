#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
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
static uint32_t proxy_ip = 0;
static int hooking_active = 0;

#pragma mark - Logging

static void log_msg(const char *msg) {
    FILE *f = fopen("/tmp/proxy_log.txt", "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

#pragma mark - Banner

static void show_banner(NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = nil;

        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                for (UIWindow *w in scene.windows) {
                    if (w.isKeyWindow) {
                        window = w;
                        break;
                    }
                }
            }
        }

        if (!window) return;

        UIView *banner = [[UIView alloc] initWithFrame:CGRectMake(0, 60, window.bounds.size.width, 50)];
        banner.backgroundColor = [UIColor colorWithRed:0.0 green:0.7 blue:0.3 alpha:0.95];
        banner.alpha = 0;

        UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(12, 6, banner.bounds.size.width - 24, 38)];
        label.text = message;
        label.textColor = [UIColor whiteColor];
        label.font = [UIFont boldSystemFontOfSize:13];
        label.textAlignment = NSTextAlignmentCenter;

        [banner addSubview:label];
        [window addSubview:banner];

        [UIView animateWithDuration:0.4 animations:^{
            banner.alpha = 1.0;
        } completion:^(BOOL done) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                [UIView animateWithDuration:0.4 animations:^{
                    banner.alpha = 0;
                } completion:^(BOOL d) {
                    [banner removeFromSuperview];
                }];
            });
        }];
    });
}

#pragma mark - Proxy

static void resolve_proxy() {
    if (proxy_ip != 0) return;

    struct hostent *he = gethostbyname(PROXY_HOST);
    if (he && he->h_addrtype == AF_INET) {
        memcpy(&proxy_ip, he->h_addr_list[0], 4);
        log_msg("Proxy resolved");
    } else {
        log_msg("Proxy resolve failed");
    }
}

static int socks5_handshake(int sockfd, const char *dest_ip, int dest_port) {
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    if (send(sockfd, greeting, 3, 0) < 0) return -1;

    uint8_t resp[2];
    if (recv(sockfd, resp, 2, 0) < 2) return -1;
    if (resp[1] != 0x00) return -1;

    struct in_addr ipv4;
    if (inet_pton(AF_INET, dest_ip, &ipv4) != 1) return -1;

    uint8_t req[10] = {
        0x05, 0x01, 0x00, 0x01
    };

    memcpy(req + 4, &ipv4, 4);
    req[8] = (dest_port >> 8) & 0xFF;
    req[9] = dest_port & 0xFF;

    if (send(sockfd, req, 10, 0) < 0) return -1;

    uint8_t sresp[10];
    if (recv(sockfd, sresp, 10, 0) < 2) return -1;
    if (sresp[1] != 0x00) return -1;

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

    // Only proxy HTTPS (Roblox uses 443)
    if (dest_port != 443) {
        return orig_connect(sockfd, addr, addrlen);
    }

    char logbuf[128];
    snprintf(logbuf, sizeof(logbuf), "Intercept: %s:%d", dest_ip, dest_port);
    log_msg(logbuf);

    resolve_proxy();
    if (proxy_ip == 0) {
        log_msg("Proxy unavailable, fallback");
        return orig_connect(sockfd, addr, addrlen);
    }

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    memcpy(&proxy_addr.sin_addr, &proxy_ip, 4);
    proxy_addr.sin_port = htons(PROXY_PORT);

    hooking_active = 1;
    int result = orig_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    hooking_active = 0;

    if (result != 0) {
        log_msg("Proxy connect failed, fallback");
        return orig_connect(sockfd, addr, addrlen);
    }

    if (socks5_handshake(sockfd, dest_ip, dest_port) != 0) {
        log_msg("SOCKS failed, fallback");
        return orig_connect(sockfd, addr, addrlen);
    }

    log_msg("Proxy success");
    return 0;
}

#pragma mark - Init

__attribute__((constructor))
static void init() {
    rebind_symbols((struct rebinding[1]){
        {"connect", hook_connect, (void **)&orig_connect}
    }, 1);

    log_msg("=== Tweak Loaded ===");

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        show_banner(@"🟢 Proxy Active → roundhouse.proxy.rlwy.net");
    });
}
