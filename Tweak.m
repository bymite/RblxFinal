#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
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
static int is_hooking = 0;

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
        if (logLines.count > 50) [logLines removeObjectAtIndex:0];
        if (logView) {
            logView.text = [logLines componentsJoinedByString:@"\n"];
            [logView scrollRangeToVisible:NSMakeRange(logView.text.length, 0)];
        }
    });
}

static void setup_log_ui(UIWindow *window) {
    if (logView) return;
    UIView *container = [[UIView alloc] initWithFrame:CGRectMake(0, window.bounds.size.height * 0.5, window.bounds.size.width, window.bounds.size.height * 0.5)];
    container.backgroundColor = [UIColor colorWithWhite:0 alpha:0.7];
    container.userInteractionEnabled = NO;
    logView = [[UITextView alloc] initWithFrame:CGRectMake(5, 5, container.bounds.size.width-10, container.bounds.size.height-10)];
    logView.backgroundColor = [UIColor clearColor];
    logView.textColor = [UIColor greenColor];
    logView.font = [UIFont fontWithName:@"Courier" size:10];
    logView.editable = NO;
    [container addSubview:logView];
    [window addSubview:container];
}

#pragma mark - Network Logic

static void ensure_tunnel() {
    if (tunnel_fd != -1) return;
    is_hooking = 1;
    tunnel_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PROXY_PORT);
    struct hostent *he = gethostbyname(PROXY_HOST);
    if (!he) { proxy_log(@"❌ DNS Fail"); is_hooking = 0; return; }
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    if (orig_connect(tunnel_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        proxy_log(@"❌ Tunnel Fail");
        close(tunnel_fd);
        tunnel_fd = -1;
    } else {
        proxy_log(@"✅ Tunnel Connected");
    }
    is_hooking = 0;
}

static int hook_connect(int s, const struct sockaddr *addr, socklen_t len) {
    return orig_connect(s, addr, len);
}

static ssize_t hook_sendto(int s, const void *buf, size_t len, int f, const struct sockaddr *d, socklen_t al) {
    if (is_hooking) return orig_sendto(s, buf, len, f, d, al);
    int type; socklen_t slen = sizeof(type);
    getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &slen);
    if (type == SOCK_DGRAM) {
        game_fd = s;
        ensure_tunnel();
        if (tunnel_fd != -1) {
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
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2*NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        UIWindow *window = [UIApplication sharedApplication].keyWindow;
        if (window) setup_log_ui(window);
        proxy_log(@"🟢 Tweak Ready");
    });
}
