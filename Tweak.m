#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/runtime.h>

#define PROXY_HOST "roundhouse.proxy.rlwy.net"
#define PROXY_PORT 58298

#pragma mark - Live Log UI

static UITextView *logView = nil;
static NSMutableArray *logLines = nil;

static void proxy_log(NSString *fmt, ...) {
    va_list args; va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[ProxyTweak] %@", msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!logLines) logLines = [NSMutableArray array];
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"HH:mm:ss";
        [logLines addObject:[NSString stringWithFormat:@"%@ %@", [df stringFromDate:[NSDate date]], msg]];
        if (logLines.count > 100) [logLines removeObjectAtIndex:0];
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

#pragma mark - Proxy dict

static NSDictionary *socks5Dict() {
    return @{
        @"SOCKSEnable": @1,
        @"SOCKSProxy":  @PROXY_HOST,
        @"SOCKSPort":   @PROXY_PORT,
    };
}

#pragma mark - NSURLSession hooks

static NSURLSessionConfiguration *(*orig_defaultConfig)(id, SEL);
static NSURLSessionConfiguration *hook_defaultConfig(id self, SEL _cmd) {
    proxy_log(@"[Session] default");
    NSURLSessionConfiguration *c = orig_defaultConfig(self, _cmd);
    c.connectionProxyDictionary = socks5Dict();
    return c;
}

static NSURLSessionConfiguration *(*orig_ephemeralConfig)(id, SEL);
static NSURLSessionConfiguration *hook_ephemeralConfig(id self, SEL _cmd) {
    proxy_log(@"[Session] ephemeral");
    NSURLSessionConfiguration *c = orig_ephemeralConfig(self, _cmd);
    c.connectionProxyDictionary = socks5Dict();
    return c;
}

static id (*orig_sessionWithConfig)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
static id hook_sessionWithConfig(id self, SEL _cmd, NSURLSessionConfiguration *config,
                                  id delegate, NSOperationQueue *queue) {
    proxy_log(@"[Session] sessionWithConfig");
    if (config) config.connectionProxyDictionary = socks5Dict();
    return orig_sessionWithConfig(self, _cmd, config, delegate, queue);
}

// Log ALL task types
static id (*orig_dataTaskWithRequest)(id, SEL, NSURLRequest *, id);
static id hook_dataTaskWithRequest(id self, SEL _cmd, NSURLRequest *req, id completion) {
    proxy_log(@"[HTTP req] %@ %@", req.HTTPMethod ?: @"GET", req.URL.absoluteString ?: @"?");
    return orig_dataTaskWithRequest(self, _cmd, req, completion);
}

static id (*orig_dataTaskWithURL)(id, SEL, NSURL *, id);
static id hook_dataTaskWithURL(id self, SEL _cmd, NSURL *url, id completion) {
    proxy_log(@"[HTTP url] %@", url.absoluteString ?: @"?");
    return orig_dataTaskWithURL(self, _cmd, url, completion);
}

#pragma mark - Init

__attribute__((constructor))
static void init() {
    // NSURLSession config hooks
    Method m1 = class_getClassMethod([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration));
    orig_defaultConfig = (void *)method_getImplementation(m1);
    method_setImplementation(m1, (IMP)hook_defaultConfig);

    Method m2 = class_getClassMethod([NSURLSessionConfiguration class], @selector(ephemeralSessionConfiguration));
    orig_ephemeralConfig = (void *)method_getImplementation(m2);
    method_setImplementation(m2, (IMP)hook_ephemeralConfig);

    Method m3 = class_getClassMethod([NSURLSession class], @selector(sessionWithConfiguration:delegate:delegateQueue:));
    orig_sessionWithConfig = (void *)method_getImplementation(m3);
    method_setImplementation(m3, (IMP)hook_sessionWithConfig);

    Method m4 = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithRequest:completionHandler:));
    orig_dataTaskWithRequest = (void *)method_getImplementation(m4);
    method_setImplementation(m4, (IMP)hook_dataTaskWithRequest);

    Method m5 = class_getInstanceMethod([NSURLSession class], @selector(dataTaskWithURL:completionHandler:));
    orig_dataTaskWithURL = (void *)method_getImplementation(m5);
    method_setImplementation(m5, (IMP)hook_dataTaskWithURL);

    proxy_log(@"🟢 Loaded (NSURLSession only). %s:%d", PROXY_HOST, PROXY_PORT);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5*NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        UIWindow *window = nil;
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes)
            if ([scene isKindOfClass:[UIWindowScene class]])
                for (UIWindow *w in ((UIWindowScene *)scene).windows)
                    if (w.isKeyWindow) { window = w; break; }
        if (window) setup_log_ui(window);
        proxy_log(@"Log UI ready — watching all HTTP");
    });
}
