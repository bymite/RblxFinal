#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
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

static void resolve_proxy() {
    if (proxy_ip != 0) return;
    struct hostent *he = gethostbyname(PROXY_HOST);
    if (he) memcpy(&proxy_ip, he->h_addr_list[0], 4);
}

// Bypasses local DNS by sending the domain name directly to Railway
static int socks5_handshake_remote_dns(int sockfd, const char *domain, int dest_port) {
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    if (send(sockfd, greeting, 3, 0) < 0) return -1;
    uint8_t resp[2];
    if (recv(sockfd, resp, 2, 0) < 2 || resp[1] != 0x00) return -1;

    uint8_t req[512];
    int i = 0;
    req[i++] = 0x05; 
    req[i++] = 0x01; 
    req[i++] = 0x00; 
    req[i++] = 0x03; // ATYP: Domain Name (Remote DNS)
    
    size_t domain_len = strlen(domain);
    req[i++] = (uint8_t)domain_len;
    memcpy(&req[i], domain, domain_len);
    i += domain_len;
    
    req[i++] = (dest_port >> 8) & 0xFF;
    req[i++] = dest_port & 0xFF;

    if (send(sockfd, req, i, 0) < 0) return -1;
    uint8_t sresp[10];
    if (recv(sockfd, sresp, 10, 0) < 2 || sresp[1] != 0x00) return -1;

    return 0;
}

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr || hooking_active || addr->sa_family != AF_INET)
        return orig_connect(sockfd, addr, addrlen);

    struct sockaddr_in *s = (struct sockaddr_in *)addr;
    int dest_port = ntohs(s->sin_port);

    if (dest_port != 443) return orig_connect(sockfd, addr, addrlen);

    resolve_proxy();
    if (proxy_ip == 0) return orig_connect(sockfd, addr, addrlen);

    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    memcpy(&proxy_addr.sin_addr, &proxy_ip, 4);
    proxy_addr.sin_port = htons(PROXY_PORT);

    hooking_active = 1;
    int result = orig_connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr));
    hooking_active = 0;

    if (result == 0) {
        if (socks5_handshake_remote_dns(sockfd, "roblox.com", dest_port) != 0) return -1;
        return 0;
    }
    return orig_connect(sockfd, addr, addrlen);
}

__attribute__((constructor))
static void init() {
    rebind_symbols((struct rebinding[1]){{"connect", hook_connect, (void **)&orig_connect}}, 1);
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        UIWindow *window = nil;
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                window = scene.windows.firstObject;
                break;
            }
        }
        if (window) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Proxy Running" 
                message:@"Remote DNS Bypass Active" preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [window.rootViewController presentViewController:alert animated:YES completion:nil];
        }
    });
}
