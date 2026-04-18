#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>
#import <Network/Network.h>

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

#pragma mark - Live Log UI

static UITextView *logView = nil;
static NSMutableArray *logLines = nil;

static void proxy_log(NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[ProxyTweak] %@", msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!logLines) logLines = [NSMutableArray array];
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"HH:mm:ss";
        NSString *line = [NSString stringWithFormat:@"%@ %@", [df stringFromDate:[NSDate date]], msg];
        [logLines addObject:line];
        if (logLines.count > 80) [logLines removeObjectAtIndex:0];
        if (logView) {
            logView.text = [logLines componentsJoinedByString:@"\n"];
            [logView scrollRangeToVisible:NSMakeRange(logView.text.length, 0)];
        }
    });
}

static void setup_log_ui(UIWindow *window) {
    if (logView) return;
    UIView *container = [[UIView alloc] initWithFrame:CGRectMake(0,
        window.bounds.size.height * 0.45, window.bounds.size.width, window.bounds.size.height * 0.55)];
    container.backgroundColor = [UIColor colorWithWhite:0 alpha:0.75];
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(8, 4, container.bounds.size.width-16, 20)];
    title.text = @"🔌 Proxy Live Logs";
    title.textColor = [UIColor greenColor];
    title.font = [UIFont boldSystemFontOfSize:12];
    [container addSubview:title];
    logView = [[UITextView alloc] initWithFrame:CGRectMake(4, 26,
        container.bounds.size.width-8, container.bounds.size.height-30)];
    logView.backgroundColor = [UIColor clearColor];
    logView.textColor = [UIColor colorWithRed:0.2 green:1.0 blue:0.4 alpha:1.0];
    logView.font = [UIFont fontWithName:@"Menlo" size:9];
    logView.editable = NO; logView.selectable = NO;
    [container addSubview:logView];
    [window addSubview:container];
}

#pragma mark - Host Cache

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

#pragma mark - NSURLSession hooks

static NSDictionary *socks5ProxyDict() {
    return @{
        @"SOCKSEnable": @1,
        @"SOCKSProxy": @PROXY_HOST,
        @"SOCKSPort": @PROXY_PORT,
    };
}

static NSURLSessionConfiguration *(*orig_defaultConfig)(id, SEL);
static NSURLSessionConfiguration *hook_defaultConfig(id self, SEL _cmd) {
    proxy_log(@"[Session] defaultConfig hooked");
    NSURLSessionConfiguration *c = orig_defaultConfig(self, _cmd);
    c.connectionProxyDictionary = socks5ProxyDict();
    return c;
}

static NSURLSessionConfiguration *(*orig_ephemeralConfig)(id, SEL);
static NSURLSessionConfiguration *hook_ephemeralConfig(id self, SEL _cmd) {
    proxy_log(@"[Session] ephemeralConfig hooked");
    NSURLSessionConfiguration *c = orig_ephemeralConfig(self, _cmd);
    c.connectionProxyDictionary = socks5ProxyDict();
    return c;
}

static id (*orig_sessionWithConfig)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
static id hook_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *config, id delegate, NSOperationQueue *queue) {
    proxy_log(@"[Session] sessionWithConfiguration hooked");
    if (config) config.connectionProxyDictionary = socks5ProxyDict();
    return orig_sessionWithConfig(self, _cmd, config, delegate, queue);
}

#pragma mark - Network.framework hooks (NWConnection)

// Hook nw_parameters_create_secure_tcp to inject proxy into NWConnection
static nw_parameters_t (*orig_nw_parameters_create_secure_tcp)(nw_parameters_configure_protocol_block_t, nw_parameters_configure_protocol_block_t);
static nw_parameters_t hook_nw_parameters_create_secure_tcp(
    nw_parameters_configure_protocol_block_t configure_tls,
    nw_parameters_configure_protocol_block_t configure_tcp) {
    proxy_log(@"[NWConnection] nw_parameters_create_secure_tcp hooked");
    nw_parameters_t params = orig_nw_parameters_create_secure_tcp(configure_tls, configure_tcp);
    // Inject SOCKS5 proxy into NW parameters
    nw_endpoint_t proxy_endpoint = nw_endpoint_create_host(PROXY_HOST, [@(PROXY_PORT).stringValue UTF8String]);
    nw_proxy_config_t proxy_config = nw_proxy_config_create_socksv5(proxy_endpoint);
    nw_parameters_add_proxy_config(params, proxy_config);
    proxy_log(@"[NWConnection] SOCKS5 injected into NW params");
    return params;
}

static nw_parameters_t (*orig_nw_parameters_create_secure_udp)(nw_parameters_configure_protocol_block_t, nw_parameters_configure_protocol_block_t);
static nw_parameters_t hook_nw_parameters_create_secure_udp(
    nw_parameters_configure_protocol_block_t configure_dtls,
    nw_parameters_configure_protocol_block_t configure_udp) {
    proxy_log(@"[NWConnection] nw_parameters_create_secure_udp hooked");
    nw_parameters_t params = orig_nw_parameters_create_secure_udp(configure_dtls, configure_udp);
    nw_endpoint_t proxy_endpoint = nw_endpoint_create_host(PROXY_HOST, [@(PROXY_PORT).stringValue UTF8String]);
    nw_proxy_config_t proxy_config = nw_proxy_config_create_socksv5(proxy_endpoint);
    nw_parameters_add_proxy_config(params, proxy_config);
    return params;
}

#pragma mark - BSD connect hook

static void resolve_proxy() {
    if (proxy_ip != 0) return;
    hooking_active = 1;
    struct hostent *he = gethostbyname(PROXY_HOST);
    hooking_active = 0;
    if (he && he->h_addrtype == AF_INET) {
        memcpy(&proxy_ip, he->h_addr_list[0], 4);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &proxy_ip, buf, sizeof(buf));
        proxy_log(@"Proxy resolved: %s", buf);
    } else {
        proxy_log(@"❌ Proxy resolve FAILED");
    }
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
    if (send(fd, g, 3, MSG_NOSIGNAL) < 0) { proxy_log(@"❌ greeting failed"); return -1; }
    uint8_t r[2];
    if (recv(fd, r, 2, 0) < 2 || r[1] != 0x00) { proxy_log(@"❌ greeting resp bad"); return -1; }
    size_t hl = strlen(host);
    uint8_t req[7+256];
    req[0]=0x05; req[1]=0x01; req[2]=0x00; req[3]=0x03;
    req[4]=(uint8_t)hl; memcpy(req+5, host, hl);
    req[5+hl]=(port>>8)&0xFF; req[6+hl]=port&0xFF;
    if (send(fd, req, 7+hl, MSG_NOSIGNAL) < 0) { proxy_log(@"❌ req failed"); return -1; }
    uint8_t sr[10];
    if (recv(fd, sr, 10, 0) < 2) { proxy_log(@"❌ no response"); return -1; }
    if (sr[1] != 0x00) { proxy_log(@"❌ SOCKS5 err: %d", sr[1]); return -1; }
    proxy_log(@"✅ Tunneled → %s:%d", host, port);
    return 0;
}

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr || hooking_active) return orig_connect(sockfd, addr, addrlen);
    if (addr->sa_family != AF_INET) return orig_connect(sockfd, addr, addrlen);
    struct sockaddr_in *s = (struct sockaddr_in *)addr;
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &s->sin_addr, dest_ip, sizeof(dest_ip));
    int dest_port = ntohs(s->sin_port);
    if (strncmp(dest_ip, "127.", 4) == 0) return orig_connect(sockfd, addr, addrlen);
    resolve_proxy();
    if (proxy_ip == 0 || s->sin_addr.s_addr == proxy_ip) return orig_connect(sockfd, addr, addrlen);
    const char *hostname = lookup_host(s->sin_addr.s_addr);
    const char *dest = hostname ? hostname : dest_ip;
    proxy_log(@"[connect] → %s:%d", dest, dest_port);
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);
    struct sockaddr_in px;
    memset(&px, 0, sizeof(px));
    px.sin_family = AF_INET;
    memcpy(&px.sin_addr, &proxy_ip, 4);
    px.sin_port = htons(PROXY_PORT);
    hooking_active = 1;
    int r = orig_connect(sockfd, (struct sockaddr *)&px, sizeof(px));
    hooking_active = 0;
    if (r != 0 && errno == EINPROGRESS) r = wait_for_connect(sockfd, 10);
    if (r != 0) {
        proxy_log(@"❌ proxy TCP failed errno=%d", errno);
        fcntl(sockfd, F_SETFL, flags);
        return orig_connect(sockfd, addr, addrlen);
    }
    r = socks5_handshake(sockfd, dest, dest_port);
    fcntl(sockfd, F_SETFL, flags);
    return r;
}

#pragma mark - Init

__attribute__((constructor))
static void init() {
    // BSD socket hooks
    rebind_symbols((struct rebinding[2]){
        {"connect",     hook_connect,     (void **)&orig_connect},
        {"getaddrinfo", hook_getaddrinfo, (void **)&orig_getaddrinfo},
    }, 2);

    // Network.framework hooks
    rebind_symbols((struct rebinding[2]){
        {"nw_parameters_create_secure_tcp", hook_nw_parameters_create_secure_tcp, (void **)&orig_nw_parameters_create_secure_tcp},
        {"nw_parameters_create_secure_udp", hook_nw_parameters_create_secure_udp, (void **)&orig_nw_parameters_create_secure_udp},
    }, 2);

    // NSURLSession hooks
    Method m1 = class_getClassMethod([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration));
    orig_defaultConfig = (void *)method_getImplementation(m1);
    method_setImplementation(m1, (IMP)hook_defaultConfig);

    Method m2 = class_getClassMethod([NSURLSessionConfiguration class], @selector(ephemeralSessionConfiguration));
    orig_ephemeralConfig = (void *)method_getImplementation(m2);
    method_setImplementation(m2, (IMP)hook_ephemeralConfig);

    Method m3 = class_getClassMethod([NSURLSession class], @selector(sessionWithConfiguration:delegate:delegateQueue:));
    orig_sessionWithConfig = (void *)method_getImplementation(m3);
    method_setImplementation(m3, (IMP)hook_sessionWithConfig);

    proxy_log(@"🟢 Dylib loaded. Proxy: %s:%d", PROXY_HOST, PROXY_PORT);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5*NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        UIWindow *window = nil;
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes)
            if ([scene isKindOfClass:[UIWindowScene class]])
                for (UIWindow *w in ((UIWindowScene *)scene).windows)
                    if (w.isKeyWindow) { window = w; break; }
        if (window) setup_log_ui(window);
        proxy_log(@"Log UI ready");
    });
}
