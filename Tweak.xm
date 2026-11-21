// MTDeviceSpoof — 美团 iOS 12.69.201 全量设备信息接管
// 目标: com.meituan.imeituan
// 环境: TrollStore + TrollFools 注入（无越狱） / 也可做越狱插件
//
// 设计原则:
//   1) 只改"能区分个体"的字段，不动"型号级"字段（屏幕/语言/时区），
//      避免机型与屏幕交叉校验时反而露馅，也避免 UI 布局崩坏
//   2) 一套伪档案持久化 + 自洽（同一 App 生命周期内稳定）
//   3) keychain 的读与写都接管 —— 美团会记录 delete_keychain + old_uuid
//   4) 屏蔽注入痕迹、越狱痕迹、TrollStore 痕迹、调试痕迹

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <CoreMotion/CoreMotion.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <NetworkExtension/NEHotspotNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <sys/ptrace.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <string.h>

#pragma mark - ========== 0. 伪档案 ==========

static NSString *MTStorePath(void) {
    static NSString *p;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *lib = [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory,
                                                             NSUserDomainMask, YES) firstObject];
        NSString *dir = [lib stringByAppendingPathComponent:@"Preferences"];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        p = [dir stringByAppendingPathComponent:@"com.mt.spoof.plist"];
    });
    return p;
}

@interface MTProfile : NSObject
@property (nonatomic, strong) NSMutableDictionary *d;
@end

@implementation MTProfile

+ (instancetype)shared {
    static MTProfile *s; static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = [MTProfile new];
        s.d = [[NSDictionary dictionaryWithContentsOfFile:MTStorePath()] mutableCopy]
              ?: [NSMutableDictionary dictionary];
        NSLog(@"[SPOOF] profile loaded (%d keys) path=%@", (int)s.d.count, MTStorePath());
    });
    return s;
}

- (NSString *)randHex:(int)n {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n; i++) [s appendFormat:@"%x", arc4random_uniform(16)];
    return s;
}

// 取或生成（生成后立即落盘，保证后续稳定）
- (id)val:(NSString *)k gen:(id(^)(void))gen {
    id v = self.d[k];
    if (!v) {
        v = gen();
        if (v) { self.d[k] = v; [self.d writeToFile:MTStorePath() atomically:YES]; }
    }
    return v;
}

- (NSString *)uuid    { return [self val:@"uuid"    gen:^id{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)idfv    { return [self val:@"idfv"    gen:^id{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)idfa    { return [self val:@"idfa"    gen:^id{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)dpid    { return [self val:@"dpid"    gen:^id{ return [self randHex:16]; }]; }
- (NSString *)unionid { return [self val:@"unionid" gen:^id{ return [self randHex:32]; }]; }

// WiFi：BSSID 必须是合法 MAC 形态（xx:xx:xx:xx:xx:xx）
- (NSString *)bssid {
    return [self val:@"bssid" gen:^id{
        NSMutableArray *a = [NSMutableArray array];
        for (int i = 0; i < 6; i++) [a addObject:[NSString stringWithFormat:@"%02x", arc4random_uniform(256)]];
        return [a componentsJoinedByString:@":"];
    }];
}
- (NSString *)ssid {
    NSArray<NSString *> *pool = @[@"ChinaNet", @"CMCC-5G", @"TP-LINK_5G", @"HUAWEI-2.4G", @"Xiaomi_Router"];
    return [self val:@"ssid" gen:^id{ return pool[arc4random_uniform((uint32_t)pool.count)]; }];
}

// 存储/内存：给一组常见值，避免暴露真实容量
- (NSNumber *)totalDisk {
    return [self val:@"totalDisk" gen:^id{ return @(128ULL * 1000 * 1000 * 1000); }];
}
- (NSNumber *)freeDisk {
    return [self val:@"freeDisk" gen:^id{ return @(32ULL * 1000 * 1000 * 1000 + arc4random_uniform(20) * 1000000000ULL); }];
}
- (NSNumber *)physicalMem {
    return [self val:@"physicalMem" gen:^id{ return @(4ULL * 1024 * 1024 * 1024); }];
}

// 电闸：给一个中位值，避免"100% 或 3%"这种异常值
- (float)batteryLevel {
    return [[self val:@"battery" gen:^id{ return @(0.55f + arc4random_uniform(30) / 100.0f); }] floatValue];
}

@end

#pragma mark - ========== 1. 设备标识 ==========

%hook UIDevice
- (NSUUID *)identifierForVendor {
    NSUUID *n = [[NSUUID alloc] initWithUUIDString:[MTProfile shared].idfv];
    return n ?: %orig;
}
- (NSString *)name {
    // 设备名常含真实姓名（"张三的 iPhone"），统一成通用名
    return @"iPhone";
}
- (float)batteryLevel { return [MTProfile shared].batteryLevel; }
- (UIDeviceBatteryState)batteryState { return UIDeviceBatteryStateUnplugged; }
%end

%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    NSUUID *n = [[NSUUID alloc] initWithUUIDString:[MTProfile shared].idfa];
    return n ?: %orig;
}
- (BOOL)isAdvertisingTrackingEnabled { return YES; }
%end

#pragma mark - ========== 2. keychain（读+写都接管）==========

// 美团 keychain account:
//   com.meituan.kONIPrivateKeychainValueUUID / DPID / UnionID
//   com.meituan.kONISharedKeychainValueUUID  / DPID / UnionID
static NSString *MTSpoofForKey(id acct) {
    if (![acct isKindOfClass:[NSString class]]) return nil;
    NSString *s = (NSString *)acct;
    MTProfile *p = [MTProfile shared];
    if ([s rangeOfString:@"KeychainValueUUID"].location    != NSNotFound) return p.uuid;
    if ([s rangeOfString:@"KeychainValueDPID"].location    != NSNotFound) return p.dpid;
    if ([s rangeOfString:@"KeychainValueUnionID"].location != NSNotFound) return p.unionid;
    return nil;
}

%hookf(OSStatus, SecItemCopyMatching, CFDictionaryRef query, CFTypeRef *result) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    NSString *fake = MTSpoofForKey(q[(__bridge id)kSecAttrAccount]);
    if (fake && result) {
        if ([q[(__bridge id)kSecReturnData] boolValue]) {
            *result = CFBridgingRetain([fake dataUsingEncoding:NSUTF8StringEncoding]);
        } else {
            NSMutableDictionary *m = [@{
                (__bridge id)kSecAttrAccount: q[(__bridge id)kSecAttrAccount] ?: @"",
                (__bridge id)kSecAttrService: q[(__bridge id)kSecAttrService] ?: @"",
            } mutableCopy];
            if ([q[(__bridge id)kSecReturnAttributes] boolValue])
                m[(__bridge id)kSecValueData] = [fake dataUsingEncoding:NSUTF8StringEncoding];
            *result = CFBridgingRetain(m);
        }
        return errSecSuccess;
    }
    return %orig;
}
%end

%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    NSMutableDictionary *m = [(__bridge NSDictionary *)attributes mutableCopy];
    NSString *fake = MTSpoofForKey(m[(__bridge id)kSecAttrAccount]);
    if (fake) {
        m[(__bridge id)kSecValueData] = [fake dataUsingEncoding:NSUTF8StringEncoding];
        return %orig((__bridge CFDictionaryRef)m, result);
    }
    return %orig;
}
%end

%hookf(OSStatus, SecItemUpdate, CFDictionaryRef query, CFDictionaryRef attrs) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    NSString *fake = MTSpoofForKey(q[(__bridge id)kSecAttrAccount]);
    if (fake) {
        NSMutableDictionary *m = [(__bridge NSDictionary *)attrs mutableCopy];
        m[(__bridge id)kSecValueData] = [fake dataUsingEncoding:NSUTF8StringEncoding];
        return %orig(query, (__bridge CFDictionaryRef)m);
    }
    return %orig;
}
%end

#pragma mark - ========== 3. 硬件标识（sysctl / uname）==========

// 只改能区分个体的容量/核心数，不改机型（机型与屏幕强绑定，改了反而露馅）
%hookf(int, sysctlbyname, const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (!name || !oldp || !oldlenp) return %orig;

    // 高频调用：全部走 strcmp，避免每次构造 NSString
    if (strcmp(name, "hw.memsize") == 0) {
        uint64_t v = [[MTProfile shared].physicalMem unsignedLongLongValue];
        if (*oldlenp >= sizeof(v)) { memcpy(oldp, &v, sizeof(v)); *oldlenp = sizeof(v); return 0; }
        return %orig;
    }
    if (strcmp(name, "hw.ncpu") == 0 ||
        strcmp(name, "hw.physicalcpu") == 0 ||
        strcmp(name, "hw.logicalcpu") == 0) {
        int32_t iv = 6;
        if (*oldlenp >= sizeof(iv)) { memcpy(oldp, &iv, sizeof(iv)); *oldlenp = sizeof(iv); return 0; }
        return %orig;
    }
    if (strcmp(name, "hw.pagesize") == 0) {
        int32_t iv = 16384;
        if (*oldlenp >= sizeof(iv)) { memcpy(oldp, &iv, sizeof(iv)); *oldlenp = sizeof(iv); return 0; }
        return %orig;
    }
    return %orig;
}
%end

// 内核版本串里带真实构建信息
%hookf(int, uname, struct utsname *buf) {
    int r = %orig;
    if (r == 0 && buf) {
        strncpy(buf->version, "Darwin Kernel Version 21.6.0", sizeof(buf->version) - 1);
    }
    return r;
}
%end

#pragma mark - ========== 4. 网络标识（WiFi / 运营商）==========

// iOS 15 仍可用（已废弃但未移除）
%hookf(CFDictionaryRef, CNCopyCurrentNetworkInfo, CFStringRef interfaceName) {
    NSDictionary *d = @{
        @"SSID":     [MTProfile shared].ssid,
        @"BSSID":    [MTProfile shared].bssid,
        @"SSIDDATA": [[MTProfile shared].ssid dataUsingEncoding:NSUTF8StringEncoding],
    };
    return (__bridge_retained CFDictionaryRef)d;
}
%end

%hook NEHotspotNetwork
- (NSString *)SSID       { return [MTProfile shared].ssid; }
- (NSString *)BSSID      { return [MTProfile shared].bssid; }
%end

%hook CTCarrier
- (NSString *)carrierName        { return @"中国移动"; }
- (NSString *)mobileCountryCode  { return @"460"; }
- (NSString *)mobileNetworkCode  { return @"00"; }
- (NSString *)isoCountryCode     { return @"cn"; }
%end

// 系统代理检测：一律返回"无代理"
%hookf(CFDictionaryRef, CFNetworkCopySystemProxySettings) {
    return (__bridge_retained CFDictionaryRef)@{};
}
%end

#pragma mark - ========== 5. 存储 / 内存 ==========

%hook NSFileManager
- (NSDictionary *)attributesOfFileSystemForPath:(NSString *)path error:(NSError **)err {
    NSDictionary *real = %orig;
    if (!real) return real;
    NSMutableDictionary *m = [real mutableCopy];
    m[NSFileSystemSize]     = [MTProfile shared].totalDisk;
    m[NSFileSystemFreeSize] = [MTProfile shared].freeDisk;
    return m;
}
%end

%hook NSProcessInfo
- (unsigned long long)physicalMemory { return [[MTProfile shared].physicalMem unsignedLongLongValue]; }
- (NSUInteger)processorCount          { return 6; }
- (NSUInteger)activeProcessorCount    { return 6; }
%end

#pragma mark - ========== 6. 电池（已在 §1 的 UIDevice hook 中处理）==========

#pragma mark - ========== 7. 剪贴板隔离 ==========

// 剪贴板内容会暴露"用户刚复制了什么"（含手机号/地址），风控也会采集
%hook UIPasteboard
- (NSString *)string {
    if (self == [UIPasteboard generalPasteboard]) return @"";
    return %orig;
}
- (NSArray *)strings {
    if (self == [UIPasteboard generalPasteboard]) return @[];
    return %orig;
}
- (NSArray *)items {
    if (self == [UIPasteboard generalPasteboard]) return @[];
    return %orig;
}
- (NSInteger)changeCount {
    if (self == [UIPasteboard generalPasteboard]) return 0;
    return %orig;
}
%end

#pragma mark - ========== 8. 已装应用探测 ==========

// 风控最爱用 canOpenURL 探测同类 App / 作弊工具是否安装
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    NSString *s = url.scheme.lowercaseString;
    if (!s) return NO;
    NSArray *blocked = @[
        @"cydia", @"sileo", @"zbra", @"filza", @"activator",
        @"trollstore", @"apple-magnifier", @"undecimus",
        @"frida", @"objection", @"cycript",
        @"alipay", @"taobao", @"pinduoduo", @"douyin",
        @"fakelocation", @"upgeo",
    ];
    if ([blocked containsObject:s]) return NO;
    return %orig;
}
%end

%hook LSApplicationWorkspace
- (NSArray *)allInstalledApplications {
    // 只回系统的，屏蔽第三方列表
    NSArray *real = %orig;
    NSMutableArray *keep = [NSMutableArray array];
    for (id app in real) {
        @try {
            NSString *bid = [app valueForKey:@"applicationIdentifier"];
            if ([bid hasPrefix:@"com.apple."]) [keep addObject:app];
        } @catch (__unused NSException *e) {}
    }
    return keep;
}
%end

#pragma mark - ========== 9. 越狱 / TrollStore / 注入痕迹 ==========

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if ([path isKindOfClass:[NSString class]]) {
        NSArray *bad = @[
            @"/Applications/Cydia.app", @"/private/jailbreak.txt",
            @"/private/var/lib/cydia",  @"/Applications/Sileo.app",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"/usr/lib/libsubstrate.dylib", @"/usr/lib/libhooker.dylib",
            @"/var/jb", @"/var/containers/Bundle/Application/.trollstore",
        ];
        for (NSString *b in bad) if ([path hasPrefix:b]) return NO;
    }
    return %orig;
}
%end

%hookf(char *, getenv, const char *name) {
    if (name) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) return NULL;
        if (strcmp(name, "_MSSafeMode") == 0)           return NULL;
    }
    return %orig;
}
%end

// 从镜像列表里剔除自己
%hookf(const char *, _dyld_get_image_name, uint32_t idx) {
    const char *n = %orig;
    if (n && (strstr(n, "MTDeviceSpoof") || strstr(n, "Substrate") || strstr(n, "substrate")))
        return NULL;
    return n;
}
%end

// 反调试：ptrace(PT_DENY_ATTACH) 会把调试器顶掉，这里直接放行
%hookf(int, ptrace, int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31 /* PT_DENY_ATTACH */) return 0;
    return %orig;
}
%end

#pragma mark - ========== 10. delete_keychain 标记 ==========

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

#pragma mark - ========== 11. 传感器噪声（反机器人）==========
// CIPPSSensorRecorder 会按时间段录制加速度计做行为指纹；
// 这里不动数据本身，只让"读取失败"变成"不可用"，避免被当异常
%hook CMMotionManager
- (BOOL)isAccelerometerAvailable { return NO; }
- (BOOL)isGyroAvailable          { return NO; }
- (BOOL)isDeviceMotionAvailable  { return NO; }
%end

#pragma mark - ========== 12. 诊断 ==========

static void MTDump(const char *name) {
    Class c = objc_getClass(name);
    if (!c) { NSLog(@"[SPOOF] class %s absent", name); return; }
    unsigned n = 0; Method *ms = class_copyMethodList(c, &n);
    for (unsigned i = 0; i < n; i++) NSLog(@"[SPOOF] -[%s %s]", name, sel_getName(method_getName(ms[i])));
    free(ms);
    ms = class_copyMethodList(object_getClass(c), &n);
    for (unsigned i = 0; i < n; i++) NSLog(@"[SPOOF] +[%s %s]", name, sel_getName(method_getName(ms[i])));
    free(ms);
}

%ctor {
    NSLog(@"[SPOOF] active in %@ v%@",
          [[NSBundle mainBundle] bundleIdentifier],
          [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]);

    // 首轮把没把握的类的方法名打出来，供下一版精确 hook
    MTDump("SAKGuardDeviceFingerprint");
    MTDump("ONIKeychainStorage");
    MTDump("SAKGuardLocalIDKeychainStorage");
    MTDump("CIPPSSensorRecorder");
    MTDump("MTSecureWifiInfo");
    MTDump("QCSFingerprintGenerator");

    MTProfile *p = [MTProfile shared];
    NSLog(@"[SPOOF] uuid=%@ dpid=%@ bssid=%@", p.uuid, p.dpid, p.bssid);
}
