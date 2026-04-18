#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

// Use the standard CFProxy keys to avoid "unavailable" errors
#define PROXY_HOST @"roundhouse.proxy.rlwy.net"
#define PROXY_PORT @58298

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
    
    // Using modern CFProxy keys to fix the Build Error
    NSDictionary *proxyDict = @{
        (id)kCFProxyTypeKey: (id)kCFProxyTypeHTTP,
        (id)kCFProxyHostNameKey: PROXY_HOST,
        (id)kCFProxyPortNumberKey: PROXY_PORT,
    };
    
    config.connectionProxyDictionary = proxyDict;
    return config;
}
@end

__attribute__((constructor))
static void init() {
    swizzle([NSURLSessionConfiguration class], 
            @selector(defaultSessionConfiguration), 
            @selector(hooked_defaultSessionConfiguration));
            
    swizzle([NSURLSessionConfiguration class], 
            @selector(ephemeralSessionConfiguration), 
            @selector(hooked_defaultSessionConfiguration));

    // Fixed UI notification logic for modern iOS
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIWindow *window = nil;
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                window = scene.windows.firstObject;
                break;
            }
        }
        
        if (window) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Domain Filter" 
                                                                           message:@"Proxy Active via Railway" 
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [window.rootViewController presentViewController:alert animated:YES completion:nil];
        }
    });
}
