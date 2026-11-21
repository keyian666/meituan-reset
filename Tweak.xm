#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>

// 越狱设备用这个路径；重打包非越狱请改成沙盒内可写路径
static NSString *const kDir  = @"/var/mobile/Library/Preferences";
static NSString *const kFile = @"/var/mobile/Library/Preferences/com.mt.spoof.plist";

@interface MTDeviceSpoofer : NSObject
@property (nonatomic, strong) NSMutableDictionary *store;
@end

@implementation MTDeviceSpoofer
+ (instancetype)shared {
    static MTDeviceSpoofer *s; static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [MTDeviceSpoofer new];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:kDir]) {
            [fm createDirectoryAtPath:kDir withIntermediateDirectories:YES attributes:nil error:nil];
        }
        s.store = [[NSDictionary dictionaryWithContentsOfFile:kFile] mutableCopy]
                  ?: [NSMutableDictionary dictionary];
    });
    return s;
}
- (NSString *)hex:(int)n {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n; i++) [s appendFormat:@"%x", arc4random_uniform(16)];
    return s;
}
- (NSString *)val:(NSString *)k gen:(NSString *(^)(void))gen {
    NSString *v = self.store[k];
    if (!v.length) { v = gen(); self.store[k] = v; [self.store writeToFile:kFile atomically:YES]; }
    return v;
}
- (NSString *)uuid    { return [self val:@"uuid"    gen:^NSString *{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)idfv    { return [self val:@"idfv"    gen:^NSString *{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)idfa    { return [self val:@"idfa"    gen:^NSString *{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)dpid    { return [self val:@"dpid"    gen:^NSString *{ return [self hex:16]; }]; }
- (NSString *)unionid { return [self val:@"unionid" gen:^NSString *{ return [self hex:32]; }]; }
@end

// ---- 1. IDFV / IDFA ----
%hook UIDevice
- (NSUUID *)identifierForVendor {
    NSUUID *n = [[NSUUID alloc] initWithUUIDString:[[MTDeviceSpoofer shared] idfv]];
    return n ?: %orig;
}
%end

%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    NSUUID *n = [[NSUUID alloc] initWithUUIDString:[[MTDeviceSpoofer shared] idfa]];
    return n ?: %orig;
}
- (BOOL)isAdvertisingTrackingEnabled { return YES; }
%end

// ---- 2. Keychain：覆盖读，而不是让它读失败 ----
static NSString *MTSpoofForAccount(NSString *acct) {
    if (![acct isKindOfClass:[NSString class]]) return nil;
    if ([acct rangeOfString:@"KeychainValueUUID"].location    != NSNotFound) return [[MTDeviceSpoofer shared] uuid];
    if ([acct rangeOfString:@"KeychainValueDPID"].location    != NSNotFound) return [[MTDeviceSpoofer shared] dpid];
    if ([acct rangeOfString:@"KeychainValueUnionID"].location != NSNotFound) return [[MTDeviceSpoofer shared] unionid];
    return nil;
}

%hookf(OSStatus, SecItemCopyMatching, CFDictionaryRef query, CFTypeRef *result) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    NSString *fake = MTSpoofForAccount(q[(__bridge id)kSecAttrAccount]);
    if (fake && result) {
        BOOL wantData = [q[(__bridge id)kSecReturnData] boolValue];
        if (wantData) {
            *result = CFBridgingRetain([fake dataUsingEncoding:NSUTF8StringEncoding]);
        } else {
            NSMutableDictionary *d = [@{
                (__bridge id)kSecAttrAccount: q[(__bridge id)kSecAttrAccount] ?: @"",
                (__bridge id)kSecAttrService: q[(__bridge id)kSecAttrService] ?: @"",
            } mutableCopy];
            if ([q[(__bridge id)kSecReturnAttributes] boolValue]) {
                d[(__bridge id)kSecValueData] = [fake dataUsingEncoding:NSUTF8StringEncoding];
            }
            *result = CFBridgingRetain(d);
        }
        return errSecSuccess;
    }
    return %orig;
}
%end

// ---- 3. 越狱检测 ----
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if ([path isEqualToString:@"/Applications/Cydia.app"] ||
        [path hasPrefix:@"/private/var/lib/cydia"] ||
        [path isEqualToString:@"/private/jailbreak.txt"] ||
        [path hasPrefix:@"/Applications/Sileo"] ||
        [path hasPrefix:@"/var/jb"]) {
        return NO;
    }
    return %orig;
}
%end

// ---- 4. 把删过 keychain 的标记压成 0 ----
%hook NSUserDefaults
- (BOOL)boolForKey:(NSString *)k {
    if ([k rangeOfString:@"delete_keychain" options:NSCaseInsensitiveSearch].location != NSNotFound) return NO;
    return %orig;
}
- (id)objectForKey:(NSString *)k {
    if ([k rangeOfString:@"hasDeleteKeychain" options:NSCaseInsensitiveSearch].location != NSNotFound) return @0;
    return %orig;
}
%end

// ---- 5. 探测 SAKGuardDeviceFingerprint 的方法名（先用这个 dump，再定向 hook）----
%ctor {
    Class c = NSClassFromString(@"SAKGuardDeviceFingerprint");
    if (c) {
        unsigned int n = 0;
        Method *ms = class_copyMethodList(object_getClass(c), &n);   // 类方法
        for (unsigned i = 0; i < n; i++) NSLog(@"[SPOOF] +%s", sel_getName(method_getName(ms[i])));
        free(ms);
        ms = class_copyMethodList(c, &n);                            // 实例方法
        for (unsigned i = 0; i < n; i++) NSLog(@"[SPOOF] -%s", sel_getName(method_getName(ms[i])));
        free(ms);
    }
}
