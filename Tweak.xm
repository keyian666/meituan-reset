// MTDeviceSpoof — 为 TrollStore / TrollFools 注入设计（无越狱）
// 目标: com.meituan.imeituan  (美团 12.69.201)
//
// 设计要点:
//  1) 身份持久化在 App 沙盒内（无越狱写不了 /var/mobile）
//  2) keychain 的读和写都接管，避免"读到假值但写入旧值"
//  3) 屏蔽注入痕迹（DYLD_INSERT_LIBRARIES / 陌生镜像）
//  4) 不删除 keychain —— 美团会记录 delete_keychain + old_uuid 上报

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <objc/runtime.h>
#import <dlfcn.h>

#pragma mark - 持久化

static NSString *MTSpoofStorePath(void) {
    static NSString *path;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *lib = [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory,
                                                             NSUserDomainMask, YES) firstObject];
        NSString *dir = [lib stringByAppendingPathComponent:@"Preferences"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:nil];
        path = [dir stringByAppendingPathComponent:@"com.mt.spoof.plist"];
    });
    return path;
}

@interface MTDeviceSpoofer : NSObject
@property (nonatomic, strong) NSMutableDictionary *store;
@end

@implementation MTDeviceSpoofer

+ (instancetype)shared {
    static MTDeviceSpoofer *s;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [MTDeviceSpoofer new];
        s.store = [[NSDictionary dictionaryWithContentsOfFile:MTSpoofStorePath()] mutableCopy]
                  ?: [NSMutableDictionary dictionary];
        NSLog(@"[SPOOF] store=%d path=%@", (int)s.store.count, MTSpoofStorePath());
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
    if (!v.length) {
        v = gen();
        if (v) {
            self.store[k] = v;
            [self.store writeToFile:MTSpoofStorePath() atomically:YES];
        }
    }
    return v ?: @"";
}

// UUID 形态与真实一致（大写带连字符），避免格式校验直接命中
- (NSString *)uuid    { return [self val:@"uuid"    gen:^NSString *{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)idfv    { return [self val:@"idfv"    gen:^NSString *{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)idfa    { return [self val:@"idfa"    gen:^NSString *{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)dpid    { return [self val:@"dpid"    gen:^NSString *{ return [self hex:16]; }]; }
- (NSString *)unionid { return [self val:@"unionid" gen:^NSString *{ return [self hex:32]; }]; }

@end

#pragma mark - keychain account 映射

// 美团 keychain account 常量（从二进制符号提取）:
//   com.meituan.kONIPrivateKeychainValueUUID / DPID / UnionID
//   com.meituan.kONISharedKeychainValueUUID  / DPID / UnionID
static NSString *MTSpoofForAccount(id acct) {
    if (![acct isKindOfClass:[NSString class]]) return nil;
    NSString *s = (NSString *)acct;
    if ([s rangeOfString:@"KeychainValueUUID"].location    != NSNotFound) return [[MTDeviceSpoofer shared] uuid];
    if ([s rangeOfString:@"KeychainValueDPID"].location    != NSNotFound) return [[MTDeviceSpoofer shared] dpid];
    if ([s rangeOfString:@"KeychainValueUnionID"].location != NSNotFound) return [[MTDeviceSpoofer shared] unionid];
    return nil;
}

#pragma mark - 1. IDFV / IDFA

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

#pragma mark - 2. keychain 读

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

#pragma mark - 3. keychain 写（否则旧 UUID 会被写回去）

%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    NSMutableDictionary *m = [(__bridge NSDictionary *)attributes mutableCopy];
    NSString *fake = MTSpoofForAccount(m[(__bridge id)kSecAttrAccount]);
    if (fake) {
        m[(__bridge id)kSecValueData] = [fake dataUsingEncoding:NSUTF8StringEncoding];
        NSLog(@"[SPOOF] SecItemAdd rewrite %@", m[(__bridge id)kSecAttrAccount]);
        return %orig((__bridge CFDictionaryRef)m, result);
    }
    return %orig;
}
%end

%hookf(OSStatus, SecItemUpdate, CFDictionaryRef query, CFDictionaryRef attrs) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    NSString *fake = MTSpoofForAccount(q[(__bridge id)kSecAttrAccount]);
    if (fake) {
        NSMutableDictionary *m = [(__bridge NSDictionary *)attrs mutableCopy];
        m[(__bridge id)kSecValueData] = [fake dataUsingEncoding:NSUTF8StringEncoding];
        NSLog(@"[SPOOF] SecItemUpdate rewrite %@", q[(__bridge id)kSecAttrAccount]);
        return %orig(query, (__bridge CFDictionaryRef)m);
    }
    return %orig;
}
%end

#pragma mark - 4. 注入 / 越狱痕迹

%hookf(char *, getenv, const char *name) {
    if (name) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) return NULL;
        if (strcmp(name, "_MSSafeMode") == 0)           return NULL;
    }
    return %orig;
}
%end

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if ([path isKindOfClass:[NSString class]]) {
        if ([path isEqualToString:@"/Applications/Cydia.app"] ||
            [path isEqualToString:@"/private/jailbreak.txt"] ||
            [path hasPrefix:@"/private/var/lib/cydia"] ||
            [path hasPrefix:@"/Applications/Sileo"] ||
            [path hasPrefix:@"/var/jb"] ||
            [path hasPrefix:@"/usr/lib/libhooker"] ||
            [path hasPrefix:@"/usr/lib/libsubstrate"]) {
            return NO;
        }
    }
    return %orig;
}
%end

// 过滤掉我们自己的镜像名
%hookf(const char *, _dyld_get_image_name, uint32_t idx) {
    const char *n = %orig;
    if (n && strstr(n, "MTDeviceSpoof")) return NULL;
    return n;
}
%end

#pragma mark - 5. 删过 keychain 的标记（它会上报 old_uuid）

%hook NSUserDefaults
- (BOOL)boolForKey:(NSString *)k {
    if ([k isKindOfClass:[NSString class]] &&
        [k rangeOfString:@"delete_keychain" options:NSCaseInsensitiveSearch].location != NSNotFound)
        return NO;
    return %orig;
}
- (id)objectForKey:(NSString *)k {
    if ([k isKindOfClass:[NSString class]] &&
        [k rangeOfString:@"hasDeleteKeychain" options:NSCaseInsensitiveSearch].location != NSNotFound)
        return @0;
    return %orig;
}
%end

#pragma mark - 6. 运行时探测指纹类（首版用来定位 hook 点）

static void MTDumpClass(const char *name) {
    Class c = objc_getClass(name);
    if (!c) { NSLog(@"[SPOOF] class %s not found", name); return; }

    unsigned int n = 0;
    Method *ms = class_copyMethodList(object_getClass(c), &n);
    for (unsigned i = 0; i < n; i++)
        NSLog(@"[SPOOF] +%s", sel_getName(method_getName(ms[i])));
    free(ms);

    ms = class_copyMethodList(c, &n);
    for (unsigned i = 0; i < n; i++)
        NSLog(@"[SPOOF] -%s", sel_getName(method_getName(ms[i])));
    free(ms);
}

%ctor {
    NSLog(@"[SPOOF] loaded into %@ v%@",
          [[NSBundle mainBundle] bundleIdentifier],
          [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]);

    MTDumpClass("SAKGuardDeviceFingerprint");
    MTDumpClass("ONIKeychainStorage");
    MTDumpClass("SAKGuardLocalIDKeychainStorage");
    MTDumpClass("CIPKeychainHelper");

    // 触发一次，确保身份已生成并落盘
    (void)[[MTDeviceSpoofer shared] uuid];
}
