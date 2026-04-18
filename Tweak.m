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

// Show a banner on screen so we know the dylib is loaded
static void show_banner(NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = nil;
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if ([scene isKindOfClass:[UIWindowScene class]]) {
                window = scene.windows.firstObject;
                break;
            }
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

        [UIView animateWithDuration:0.4 animations:^{ banner.alpha = 1.0; } completion:^(BOOL done) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                [UIView animateWithDuration:0.4 animations:^{ banner.alpha = 0; } completion:^(BOOL d) {
                    [banner removeFromSuperview];
                }];
            });
        }];
    });
}

static void resolve_proxy() {
    if (proxy_ip != 0) return;
    struct hostent *he = gethostbyname(PROXY_HOST);
    if (he && he->h_addrtype == AF_INET)
        memcpy(&proxy_ip, he->h_addr_list[0], 4);
}

static int socks5_handshake(int sockfd, const char *dest_ip, int dest_port) {
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    if (send(sockfd, greeting, sizeof(greeting), 0) < 0) return -1;
    uint8_t resp[2] = {0};
    if (recv(sockfd, resp, 2, 0) < 2) return -1;
    if (resp[0] != 0x05 || resp[1] != 0x00) return -1;

    struct in_addr ipv4;
    if (inet_pton(AF_INET, dest_ip, &ipv4) == 1) {
        uint8_t req[10];
        req[0]=0x05; req[1]=0x01; req[2]=0x00; req[3]=0x01;
        memcpy(req+4, &ipv4, 4);
        req[8]=(dest_port>>8)&0xFF; req[9]=dest_port&0xFF;
        if (send(sockfd, req, 10, 0) < 0) return -1;
    } else {
        size_t hlen = strlen(dest_ip);
        uint8_t req[7 + 256];
        req[0]=0x05; req[1]=0x01; req[2]=0x00; req[3]=0x03;
        req[4]=(uint8_t)hlen;
        memcpy(req+5, dest_ip, hlen);
        req[5+hlen]=(dest_port>>8)&0xFF; req[6+hlen]=dest_port&0xFF;
        if (send(sockfd, req, 7+hlen, 0) < 0) return -1;
    }

    uint8_t sresp[10] = {0};
    if (recv(sockfd, sresp, 10, 0) < 2) return -1;
    if (sresp[0] != 0x05 || sresp[1] != 0x00) return -1;
    return 0;
}

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr || hooking_active) return orig_connect(sockfd, addr, addrlen);

    int type = 0; socklen_t tl = sizeof(type);
    getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &tl);
    if (type != SOCK_STREAM) return orig_connect(sockfd, addr, addrlen);
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
        return orig_connect(sockfd, addr, addrlen);

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

    if (strncmp(dest_ip, "127.", 4) == 0 || strcmp(dest_ip, "::1") == 0)
        return orig_connect(sockfd, addr, addrlen);

    hooking_active = 1;
    resolve_proxy();
    hooking_active = 0;

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)addr;
        if (memcmp(&s->sin_addr, &proxy_ip, 4) == 0)
            return orig_connect(sockfd, addr, addrlen);
    }

    if (proxy_ip == 0) return orig_connect(sockfd, addr, addrlen);

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    memcpy(&proxy_addr.sin_addr, &proxy_ip, 4);
    proxy_addr.sin_port = htons(PROXY_PORT);

    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

    hooking_active = 1;
    int result = orig_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    hooking_active = 0;

    if (result != 0) {
        fcntl(sockfd, F_SETFL, flags);
        return orig_connect(sockfd, addr, addrlen);
    }

    result = socks5_handshake(sockfd, dest_ip, dest_port);
    fcntl(sockfd, F_SETFL, flags);
    return result;
}

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

// Hook applicationDidBecomeActive to show banner once app is visible
static void (*orig_didBecomeActive)(id, SEL, id);
static void hook_didBecomeActive(id self, SEL _cmd, id app) {
    orig_didBecomeActive(self, _cmd, app);
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        show_banner(@"🟢 Proxy Active → roundhouse.proxy.rlwy.net:58298");
    });
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

    // Hook AppDelegate to show banner when app is ready
    Class appDelegateClass = NSClassFromString(@"AppDelegate");
    if (!appDelegateClass) appDelegateClass = NSClassFromString(@"RobloxAppDelegate");
    if (appDelegateClass) {
        Method m2 = class_getInstanceMethod(appDelegateClass,
                        @selector(applicationDidBecomeActive:));
        if (m2) {
            orig_didBecomeActive = (void *)method_getImplementation(m2);
            method_setImplementation(m2, (IMP)hook_didBecomeActive);
        }
    }
}
