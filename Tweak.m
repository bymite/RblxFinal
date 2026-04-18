#import <Foundation/Foundation.h>
#import <CFNetwork/CFNetwork.h>
#import <objc/runtime.h>

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
    Class cls = objc_getMetaClass("NSURLSessionConfiguration");

    Method m1 = class_getClassMethod([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration));
    orig_defaultConfig = (void *)method_getImplementation(m1);
    method_setImplementation(m1, (IMP)hook_defaultConfig);

    Method m2 = class_getClassMethod([NSURLSessionConfiguration class], @selector(ephemeralSessionConfiguration));
    orig_ephemeralConfig = (void *)method_getImplementation(m2);
    method_setImplementation(m2, (IMP)hook_ephemeralConfig);
}
