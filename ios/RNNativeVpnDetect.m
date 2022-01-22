
#import "RNNativeVpnDetect.h"

@implementation RNNativeVpnDetect

- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(detectVPN:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
    CFDictionaryRef cfDict = CFNetworkCopySystemProxySettings();
    NSDictionary *nsDict = (__bridge NSDictionary*)cfDict;
    NSDictionary *keys = [nsDict valueForKey:@"__SCOPED__"];
    BOOL isConnected = NO;
    
    for (id key in keys) {
        if ([@"tap" isEqual: key] || [@"tun" isEqual: key] || [@"ppp" isEqual: key] || [@"ipsec" isEqual: key] || [@"ipsec0" isEqual: key] || [key containsString: @"utun"]) {
            isConnected = YES;
        }
    }
    resolve(@(isConnected));
}
  
RCT_EXPORT_METHOD(detectProxy:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
        //resolve(@"detectProxy");
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration defaultSessionConfiguration];

    NSDictionary *proxyDict = @{
                            @"HTTPEnable"  : [NSNumber numberWithInt:1],
                            (NSString *)kCFStreamPropertyProxyLocalBypass  : @"10.26.*.*",
                            @"HTTPSEnable" : [NSNumber numberWithInt:1],
                           (NSString *)kCFStreamPropertyProxyLocalBypass  : @"10.26.*.*"
                              };
    sessionConfig.connectionProxyDictionary = proxyDict;
    
    CFDictionaryRef dicRef = CFNetworkCopySystemProxySettings();
    const CFStringRef proxyCFstr = (const CFStringRef)CFDictionaryGetValue(dicRef, (const void*)kCFNetworkProxiesHTTPProxy);
    resolve(proxyCFstr);
}

@end
