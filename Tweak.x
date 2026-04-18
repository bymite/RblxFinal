#import <Foundation/Foundation.h>

%hook NSURLSessionConfiguration

- (NSDictionary *)connectionProxyDictionary {
    return @{
        (NSString *)kCFStreamPropertyHTTPProxyHost: @"mainline.proxy.rlwy.net",
        (NSString *)kCFStreamPropertyHTTPProxyPort: @55396,
        (NSString *)kCFStreamPropertyHTTPSProxyHost: @"mainline.proxy.rlwy.net",
        (NSString *)kCFStreamPropertyHTTPSProxyPort: @55396,
    };
}

+ (NSURLSessionConfiguration *)defaultSessionConfiguration {
    NSURLSessionConfiguration *config = %orig;
    config.connectionProxyDictionary = @{
        (NSString *)kCFStreamPropertyHTTPProxyHost: @"mainline.proxy.rlwy.net",
        (NSString *)kCFStreamPropertyHTTPProxyPort: @55396,
        (NSString *)kCFStreamPropertyHTTPSProxyHost: @"mainline.proxy.rlwy.net",
        (NSString *)kCFStreamPropertyHTTPSProxyPort: @55396,
    };
    return config;
}

+ (NSURLSessionConfiguration *)ephemeralSessionConfiguration {
    NSURLSessionConfiguration *config = %orig;
    config.connectionProxyDictionary = @{
        (NSString *)kCFStreamPropertyHTTPProxyHost: @"mainline.proxy.rlwy.net",
        (NSString *)kCFStreamPropertyHTTPProxyPort: @55396,
        (NSString *)kCFStreamPropertyHTTPSProxyHost: @"mainline.proxy.rlwy.net",
        (NSString *)kCFStreamPropertyHTTPSProxyPort: @55396,
    };
    return config;
}

%end
