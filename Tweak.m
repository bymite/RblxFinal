#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#include <substrate.h>

static NSDictionary *proxyDict() {
    return @{
        (NSString *)kCFStreamPropertyHTTPProxyHost:  @"mainline.proxy.rlwy.net",
        (NSString *)kCFStreamPropertyHTTPProxyPort:  @55396,
        (NSString *)kCFStreamPropertyHTTPSProxyHost: @"mainline.proxy.rlwy.net",
        (NSString *)kCFStreamPropertyHTTPSProxyPort: @55396,
    };
}

static NSURLSessionConfiguration *(*orig_defaultConfig)(id, SEL);
static NSURLSessionConfiguration *hook_defaultConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *config = orig_defaultConfig(self, _cmd);
    config.connectionProxyDictionary = proxyDict();
    return config;
}

static NSURLSessionConfiguration *(*orig_ephemeralConfig)(id, SEL);
static NSURLSessionConfiguration *hook_ephemeralConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *config = orig_ephemeralConfig(self, _cmd);
    config.connectionProxyDictionary = proxyDict();
    return config;
}

__attribute__((constructor))
static void init() {
    MSHookMessageEx(
        objc_getMetaClass("NSURLSessionConfiguration"),
        @selector(defaultSessionConfiguration),
        (IMP)hook_defaultConfig,
        (IMP *)&orig_defaultConfig
    );
    MSHookMessageEx(
        objc_getMetaClass("NSURLSessionConfiguration"),
        @selector(ephemeralSessionConfiguration),
        (IMP)hook_ephemeralConfig,
        (IMP *)&orig_ephemeralConfig
    );
}
