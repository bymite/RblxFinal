#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

// --- Configuration ---
#define PROXY_HOST @"roundhouse.proxy.rlwy.net"
#define PROXY_PORT @58298

// --- Swizzling Helper ---
void swizzle(Class class, SEL originalSelector, SEL swizzledSelector) {
    Method originalMethod = class_getClassMethod(class, originalSelector);
    Method swizzledMethod = class_getClassMethod(class, swizzledSelector);
    method_exchangeImplementations(originalMethod, swizzledMethod);
}

@interface NSURLSessionConfiguration (ProxyHook)
@end

@implementation NSURLSessionConfiguration (ProxyHook)

+ (NSURLSessionConfiguration *)hooked_defaultSessionConfiguration {
    NSURLSessionConfiguration *config = [self hooked_defaultSessionConfiguration];
    
    // Inject the proxy settings dictionary
    NSDictionary *proxyDict = @{
        (id)kCFNetworkProxiesHTTPEnable: @1,
        (id)kCFNetworkProxiesHTTPProxy: PROXY_HOST,
        (id)kCFNetworkProxiesHTTPPort: PROXY_PORT,
        (id)kCFNetworkProxiesHTTPSEnable: @1,
        (id)kCFNetworkProxiesHTTPSProxy: PROXY_HOST,
        (id)kCFNetworkProxiesHTTPSPort: PROXY_PORT,
    };
    
    config.connectionProxyDictionary = proxyDict;
    return config;
}

@end

// --- Initialization ---
__attribute__((constructor))
static void init() {
    NSLog(@"[ProxyTweak] Initializing Domain Filter...");

    // Swizzle the default and ephemeral configurations
    // This covers almost all modern iOS network requests
    swizzle([NSURLSessionConfiguration class], 
            @selector(defaultSessionConfiguration), 
            @selector(hooked_defaultSessionConfiguration));
            
    swizzle([NSURLSessionConfiguration class], 
            @selector(ephemeralSessionConfiguration), 
            @selector(hooked_defaultSessionConfiguration));

    // Simple Alert to confirm it loaded
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Proxy Active" 
                                                                       message:@"Domain Filtering Enabled" 
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:alert animated:YES completion:nil];
    });
}
