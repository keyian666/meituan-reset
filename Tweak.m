// MTDeviceSpoof — 零依赖实现（不依赖 CydiaSubstrate / ElleKit / Logos）
// 目标: com.meituan.imeituan
// 环境: TrollStore + TrollFools（无越狱、无 substrate）
//
// ObjC 方法：method_setImplementation + imp_implementationWithBlock（保存原 IMP 并转发）
// C  函数：内联 fishhook（改写 __DATA/__DATA_CONST 中的符号指针）

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
// CoreTelephony / CoreMotion / NetworkExtension 的类一律用 NSClassFromString 访问，
// 不 import 它们的头（部分头会 #error 要求用 @import module）。
#import <SystemConfiguration/CaptiveNetwork.h>
#import <CFNetwork/CFNetwork.h>
#import <CFNetwork/CFProxySupport.h>
#import <stdlib.h>
#import <string.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/mman.h>
#import <mach-o/dyld.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <dlfcn.h>

#pragma mark - ===================== fishhook =====================

struct mt_rebinding { const char *name; void *replacement; void **replaced; };
struct mt_rebinding_entry {
    struct mt_rebinding *items;
    size_t count;
    struct mt_rebinding_entry *next;
};
static struct mt_rebinding_entry *g_rebindings = NULL;

static int mt_prepend(struct mt_rebinding_entry **head, struct mt_rebinding rb[], size_t n) {
    struct mt_rebinding_entry *e = calloc(1, sizeof(*e));
    if (!e) return -1;
    e->items = malloc(n * sizeof(*rb));
    if (!e->items) { free(e); return -1; }
    memcpy(e->items, rb, n * sizeof(*rb));
    e->count = n;
    e->next = *head;
    *head = e;
    return 0;
}

static void mt_rebind_section(const struct mach_header_64 *hdr, intptr_t slide,
                              const struct section_64 *sect,
                              const struct symtab_command *symtab,
                              const struct dysymtab_command *dysymtab,
                              struct mt_rebinding_entry *head)
{
    if (!symtab || !dysymtab) return;

    const struct nlist_64 *symtab_entries =
        (const struct nlist_64 *)((uintptr_t)hdr + symtab->symoff);
    const char *strtab = (const char *)hdr + symtab->stroff;
    const uint32_t *indirect = (const uint32_t *)((uintptr_t)hdr + dysymtab->indirectsymoff);

    uintptr_t *slots = (uintptr_t *)(uintptr_t)(slide + sect->addr);
    size_t nslots = sect->size / sizeof(uintptr_t);
    if (nslots == 0) return;

    uintptr_t pg = (uintptr_t)getpagesize();
    uintptr_t start = (uintptr_t)slots & ~(pg - 1);
    uintptr_t end = ((uintptr_t)slots + sect->size + pg - 1) & ~(pg - 1);
    if (vm_protect(mach_task_self(), (vm_address_t)start, end - start, false,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
        return;
    }

    for (size_t i = 0; i < nslots; i++) {
        uint32_t symidx = indirect[sect->reserved1 + i];
        if (symidx == INDIRECT_SYMBOL_LOCAL || symidx == INDIRECT_SYMBOL_ABS) continue;
        if (symidx >= symtab->nsyms) continue;
        const char *name = strtab + symtab_entries[symidx].n_un.n_strx;
        if (!name || name[0] == '\0') continue;
        if (name[0] == '_') name++;          // C 符号去掉前导下划线再比较

        for (struct mt_rebinding_entry *e = head; e; e = e->next) {
            for (size_t k = 0; k < e->count; k++) {
                if (e->items[k].name && strcmp(e->items[k].name, name) == 0) {
                    if (e->items[k].replaced && *e->items[k].replaced == NULL)
                        *e->items[k].replaced = (void *)slots[i];
                    slots[i] = (uintptr_t)e->items[k].replacement;
                }
            }
        }
    }
    vm_protect(mach_task_self(), (vm_address_t)start, end - start, false,
               VM_PROT_READ | VM_PROT_EXECUTE);
}

static void mt_rebind_image(const struct mach_header_64 *hdr, intptr_t slide,
                            struct mt_rebinding_entry *head)
{
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;

    uintptr_t cur = (uintptr_t)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SYMTAB)   symtab   = (const struct symtab_command *)lc;
        if (lc->cmd == LC_DYSYMTAB) dysymtab = (const struct dysymtab_command *)lc;
        cur += lc->cmdsize;
    }

    cur = (uintptr_t)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__DATA") == 0 ||
                strcmp(seg->segname, "__DATA_CONST") == 0) {
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    const struct section_64 *sect =
                        (const struct section_64 *)((uintptr_t)seg + sizeof(*seg) + j * sizeof(*sect));
                    uint32_t t = sect->flags & SECTION_TYPE;
                    if (t == S_LAZY_SYMBOL_POINTERS || t == S_NON_LAZY_SYMBOL_POINTERS) {
                        mt_rebind_section(hdr, slide, sect, symtab, dysymtab, head);
                    }
                }
            }
        }
        cur += lc->cmdsize;
    }
}

static void mt_rebind_all(struct mt_rebinding_entry *head) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        mt_rebind_image((const struct mach_header_64 *)h,
                        _dyld_get_image_vmaddr_slide(i), head);
    }
}

#pragma mark - ===================== ObjC hook helper =====================

static void mt_hook(Class cls, SEL sel, id block, IMP *orig) {
    if (!cls) { return; }
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { NSLog(@"[SPOOF] missing -[%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel)); return; }
    if (orig) *orig = method_getImplementation(m);
    method_setImplementation(m, imp_implementationWithBlock(block));
}

#pragma mark - ===================== 伪档案 =====================

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
        NSLog(@"[SPOOF] profile keys=%d path=%@", (int)s.d.count, MTStorePath());
    });
    return s;
}
- (NSString *)randHex:(int)n {
    NSMutableString *s = [NSMutableString string];
    for (int i = 0; i < n; i++) [s appendFormat:@"%x", arc4random_uniform(16)];
    return s;
}
- (id)val:(NSString *)k gen:(id(^)(void))gen {
    id v = self.d[k];
    if (!v) { v = gen(); if (v) { self.d[k] = v; [self.d writeToFile:MTStorePath() atomically:YES]; } }
    return v;
}
- (NSString *)uuid    { return [self val:@"uuid"    gen:^id{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)idfv    { return [self val:@"idfv"    gen:^id{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)idfa    { return [self val:@"idfa"    gen:^id{ return [NSUUID UUID].UUIDString; }]; }
- (NSString *)dpid    { return [self val:@"dpid"    gen:^id{ return [self randHex:16]; }]; }
- (NSString *)unionid { return [self val:@"unionid" gen:^id{ return [self randHex:32]; }]; }
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
- (NSNumber *)totalDisk { return [self val:@"totalDisk" gen:^id{ return @(128ULL*1000*1000*1000); }]; }
- (NSNumber *)freeDisk  { return [self val:@"freeDisk"  gen:^id{ return @(32ULL*1000*1000*1000 + (uint64_t)arc4random_uniform(20)*1000000000ULL); }]; }
- (NSNumber *)physMem   { return [self val:@"physMem"   gen:^id{ return @(4ULL*1024*1024*1024); }]; }
- (float)battery        { return [[self val:@"battery"  gen:^id{ return @(0.55f + arc4random_uniform(30)/100.0f); }] floatValue]; }
@end

static NSString *MTSpoofForKey(id acct) {
    if (![acct isKindOfClass:[NSString class]]) return nil;
    NSString *s = (NSString *)acct;
    MTProfile *p = [MTProfile shared];
    if ([s rangeOfString:@"KeychainValueUUID"].location    != NSNotFound) return p.uuid;
    if ([s rangeOfString:@"KeychainValueDPID"].location    != NSNotFound) return p.dpid;
    if ([s rangeOfString:@"KeychainValueUnionID"].location != NSNotFound) return p.unionid;
    return nil;
}

#pragma mark - ===================== C 函数实现 =====================

static OSStatus (*o_CopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*o_ItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*o_ItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static int      (*o_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int      (*o_uname)(struct utsname *);
static char *   (*o_getenv)(const char *);
static int      (*o_ptrace)(int, pid_t, caddr_t, int);
static CFDictionaryRef (*o_CNCopy)(CFStringRef);
static CFDictionaryRef (*o_ProxySettings)(void);
static const char *(*o_imgname)(uint32_t);

static OSStatus f_CopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    @autoreleasepool {
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
    }
    return o_CopyMatching ? o_CopyMatching(query, result) : errSecItemNotFound;
}

static OSStatus f_ItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    @autoreleasepool {
        NSDictionary *src = (__bridge NSDictionary *)attributes;
        NSString *fake = MTSpoofForKey(src[(__bridge id)kSecAttrAccount]);
        if (fake) {
            NSMutableDictionary *m = [src mutableCopy];
            m[(__bridge id)kSecValueData] = [fake dataUsingEncoding:NSUTF8StringEncoding];
            return o_ItemAdd ? o_ItemAdd((__bridge CFDictionaryRef)m, result) : errSecParam;
        }
    }
    return o_ItemAdd ? o_ItemAdd(attributes, result) : errSecParam;
}

static OSStatus f_ItemUpdate(CFDictionaryRef query, CFDictionaryRef attrs) {
    @autoreleasepool {
        NSDictionary *q = (__bridge NSDictionary *)query;
        NSString *fake = MTSpoofForKey(q[(__bridge id)kSecAttrAccount]);
        if (fake) {
            NSMutableDictionary *m = [(__bridge NSDictionary *)attrs mutableCopy];
            m[(__bridge id)kSecValueData] = [fake dataUsingEncoding:NSUTF8StringEncoding];
            return o_ItemUpdate ? o_ItemUpdate(query, (__bridge CFDictionaryRef)m) : errSecParam;
        }
    }
    return o_ItemUpdate ? o_ItemUpdate(query, attrs) : errSecParam;
}

static int f_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && oldp && oldlenp) {
        MTProfile *p = [MTProfile shared];
        if (strcmp(name, "hw.memsize") == 0) {
            uint64_t v = [p.physMem unsignedLongLongValue];
            if (*oldlenp >= sizeof(v)) { memcpy(oldp, &v, sizeof(v)); *oldlenp = sizeof(v); return 0; }
        } else if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.physicalcpu") == 0 ||
                   strcmp(name, "hw.logicalcpu") == 0) {
            int32_t v = 6;
            if (*oldlenp >= sizeof(v)) { memcpy(oldp, &v, sizeof(v)); *oldlenp = sizeof(v); return 0; }
        } else if (strcmp(name, "hw.pagesize") == 0) {
            int32_t v = 16384;
            if (*oldlenp >= sizeof(v)) { memcpy(oldp, &v, sizeof(v)); *oldlenp = sizeof(v); return 0; }
        }
    }
    return o_sysctlbyname ? o_sysctlbyname(name, oldp, oldlenp, newp, newlen) : -1;
}

static int f_uname(struct utsname *buf) {
    int r = o_uname ? o_uname(buf) : -1;
    if (r == 0 && buf) {
        memset(buf->version, 0, sizeof(buf->version));
        strncpy(buf->version, "Darwin Kernel Version 21.6.0", sizeof(buf->version) - 1);
    }
    return r;
}

static char *f_getenv(const char *name) {
    if (name && (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
                 strcmp(name, "_MSSafeMode") == 0)) return NULL;
    return o_getenv ? o_getenv(name) : NULL;
}

static int f_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31) return 0;                 // PT_DENY_ATTACH
    return o_ptrace ? o_ptrace(request, pid, addr, data) : -1;
}

static CFDictionaryRef f_CNCopy(CFStringRef ifname) {
    (void)ifname;
    MTProfile *p = [MTProfile shared];
    NSDictionary *d = @{
        @"SSID":     p.ssid,
        @"BSSID":    p.bssid,
        @"SSIDDATA": [p.ssid dataUsingEncoding:NSUTF8StringEncoding],
    };
    return (__bridge_retained CFDictionaryRef)d;
}

static CFDictionaryRef f_ProxySettings(void) {
    return (__bridge_retained CFDictionaryRef)@{};
}

static const char *f_imgname(uint32_t idx) {
    const char *n = o_imgname ? o_imgname(idx) : NULL;
    if (n && strstr(n, "MTDeviceSpoof")) return NULL;
    return n;
}

#pragma mark - ===================== ObjC hooks =====================

static IMP o_fileExists, o_canOpen, o_boolForKey, o_objectForKey;
static IMP o_pbString, o_pbStrings, o_pbItems, o_pbCount;

static void MTSetupHooks(void) {
    MTProfile *P = [MTProfile shared];

    // ---- 设备标识（纯伪造，不转发）----
    mt_hook([UIDevice class], @selector(identifierForVendor), ^NSUUID *(id self) {
        (void)self; return [[NSUUID alloc] initWithUUIDString:P.idfv];
    }, NULL);
    mt_hook([UIDevice class], @selector(name), ^NSString *(id self) {
        (void)self; return @"iPhone";
    }, NULL);
    mt_hook([UIDevice class], @selector(batteryLevel), ^float(id self) {
        (void)self; return P.battery;
    }, NULL);
    mt_hook([UIDevice class], @selector(batteryState), ^UIDeviceBatteryState(id self) {
        (void)self; return UIDeviceBatteryStateUnplugged;
    }, NULL);

    Class asim = NSClassFromString(@"ASIdentifierManager");
    if (asim) {
        mt_hook(asim, @selector(advertisingIdentifier), ^NSUUID *(id self) {
            (void)self; return [[NSUUID alloc] initWithUUIDString:P.idfa];
        }, NULL);
        mt_hook(asim, @selector(isAdvertisingTrackingEnabled), ^BOOL(id self) {
            (void)self; return YES;
        }, NULL);
    }

    // ---- 存储 / 内存（纯伪造）----
    mt_hook([NSFileManager class], @selector(attributesOfFileSystemForPath:error:),
            ^NSDictionary *(id self, NSString *path, NSError **err) {
        (void)self; (void)path; (void)err;
        return @{ NSFileSystemSize: P.totalDisk, NSFileSystemFreeSize: P.freeDisk };
    }, NULL);

    mt_hook([NSProcessInfo class], @selector(physicalMemory), ^unsigned long long(id self) {
        (void)self; return [P.physMem unsignedLongLongValue];
    }, NULL);
    mt_hook([NSProcessInfo class], @selector(processorCount), ^NSUInteger(id self) {
        (void)self; return 6;
    }, NULL);
    mt_hook([NSProcessInfo class], @selector(activeProcessorCount), ^NSUInteger(id self) {
        (void)self; return 6;
    }, NULL);

    // ---- 剪贴板：只拦通用剪贴板，其余转发 ----
    mt_hook([UIPasteboard class], @selector(string), ^NSString *(id self) {
        if (self == [UIPasteboard generalPasteboard]) return @"";
        NSString *(*f)(id, SEL) = (void *)o_pbString;
        return f ? f(self, @selector(string)) : nil;
    }, &o_pbString);

    mt_hook([UIPasteboard class], @selector(strings), ^NSArray *(id self) {
        if (self == [UIPasteboard generalPasteboard]) return @[];
        NSArray *(*f)(id, SEL) = (void *)o_pbStrings;
        return f ? f(self, @selector(strings)) : nil;
    }, &o_pbStrings);

    mt_hook([UIPasteboard class], @selector(items), ^NSArray *(id self) {
        if (self == [UIPasteboard generalPasteboard]) return @[];
        NSArray *(*f)(id, SEL) = (void *)o_pbItems;
        return f ? f(self, @selector(items)) : nil;
    }, &o_pbItems);

    mt_hook([UIPasteboard class], @selector(changeCount), ^NSInteger(id self) {
        if (self == [UIPasteboard generalPasteboard]) return 0;
        NSInteger (*f)(id, SEL) = (void *)o_pbCount;
        return f ? f(self, @selector(changeCount)) : 0;
    }, &o_pbCount);

    // ---- canOpenURL：黑名单拒绝，其余转发 ----
    mt_hook([UIApplication class], @selector(canOpenURL:), ^BOOL(id self, NSURL *url) {
        NSString *s = url.scheme.lowercaseString;
        NSArray *blocked = @[ @"cydia", @"sileo", @"zbra", @"filza", @"activator",
                              @"trollstore", @"apple-magnifier", @"undecimus",
                              @"frida", @"objection", @"cycript" ];
        if (s && [blocked containsObject:s]) return NO;
        BOOL (*f)(id, SEL, NSURL *) = (void *)o_canOpen;
        return f ? f(self, @selector(canOpenURL:), url) : NO;
    }, &o_canOpen);

    Class laws = NSClassFromString(@"LSApplicationWorkspace");
    if (laws) {
        mt_hook(laws, @selector(allInstalledApplications), ^NSArray *(id self) {
            (void)self; return @[];
        }, NULL);
    }

    // ---- 越狱路径：只拦已知路径，其余转发 ----
    mt_hook([NSFileManager class], @selector(fileExistsAtPath:), ^BOOL(id self, NSString *path) {
        if ([path isKindOfClass:[NSString class]]) {
            NSArray *bad = @[ @"/Applications/Cydia.app", @"/private/jailbreak.txt",
                              @"/private/var/lib/cydia",  @"/Applications/Sileo.app",
                              @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                              @"/usr/lib/libsubstrate.dylib", @"/usr/lib/libhooker.dylib",
                              @"/var/jb", @"/var/containers/Bundle/Application/.trollstore" ];
            for (NSString *b in bad) if ([path hasPrefix:b]) return NO;
        }
        BOOL (*f)(id, SEL, NSString *) = (void *)o_fileExists;
        return f ? f(self, @selector(fileExistsAtPath:), path) : NO;
    }, &o_fileExists);

    // ---- delete_keychain 标记：命中才改，其余转发 ----
    mt_hook([NSUserDefaults class], @selector(boolForKey:), ^BOOL(id self, NSString *k) {
        if ([k isKindOfClass:[NSString class]] &&
            [k rangeOfString:@"delete_keychain" options:NSCaseInsensitiveSearch].location != NSNotFound)
            return NO;
        BOOL (*f)(id, SEL, NSString *) = (void *)o_boolForKey;
        return f ? f(self, @selector(boolForKey:), k) : NO;
    }, &o_boolForKey);

    mt_hook([NSUserDefaults class], @selector(objectForKey:), ^id(id self, NSString *k) {
        if ([k isKindOfClass:[NSString class]] &&
            [k rangeOfString:@"hasDeleteKeychain" options:NSCaseInsensitiveSearch].location != NSNotFound)
            return @0;
        id (*f)(id, SEL, NSString *) = (void *)o_objectForKey;
        return f ? f(self, @selector(objectForKey:), k) : nil;
    }, &o_objectForKey);

    // ---- 运营商 / WiFi ----
    Class carrier = NSClassFromString(@"CTCarrier");
    if (carrier) {
        mt_hook(carrier, @selector(carrierName), ^NSString *(id self) {
            (void)self; return @"中国移动";
        }, NULL);
        mt_hook(carrier, @selector(mobileCountryCode), ^NSString *(id self) {
            (void)self; return @"460";
        }, NULL);
        mt_hook(carrier, @selector(mobileNetworkCode), ^NSString *(id self) {
            (void)self; return @"00";
        }, NULL);
        mt_hook(carrier, @selector(isoCountryCode), ^NSString *(id self) {
            (void)self; return @"cn";
        }, NULL);
    }

    Class neh = NSClassFromString(@"NEHotspotNetwork");
    if (neh) {
        mt_hook(neh, @selector(SSID), ^NSString *(id self) { (void)self; return P.ssid; }, NULL);
        mt_hook(neh, @selector(BSSID), ^NSString *(id self) { (void)self; return P.bssid; }, NULL);
    }

    // ---- 传感器可用性 ----
    Class mm = NSClassFromString(@"CMMotionManager");
    if (mm) {
        mt_hook(mm, @selector(isAccelerometerAvailable), ^BOOL(id self) { (void)self; return NO; }, NULL);
        mt_hook(mm, @selector(isGyroAvailable), ^BOOL(id self) { (void)self; return NO; }, NULL);
        mt_hook(mm, @selector(isDeviceMotionAvailable), ^BOOL(id self) { (void)self; return NO; }, NULL);
    }
}

#pragma mark - ===================== 诊断 =====================

static void MTDump(const char *name) {
    Class c = objc_getClass(name);
    if (!c) { NSLog(@"[SPOOF] class %s absent", name); return; }
    unsigned n = 0;
    Method *ms = class_copyMethodList(c, &n);
    for (unsigned i = 0; i < n; i++) NSLog(@"[SPOOF] -[%s %s]", name, sel_getName(method_getName(ms[i])));
    free(ms);
    ms = class_copyMethodList(object_getClass(c), &n);
    for (unsigned i = 0; i < n; i++) NSLog(@"[SPOOF] +[%s %s]", name, sel_getName(method_getName(ms[i])));
    free(ms);
}

#pragma mark - ===================== 入口 =====================

__attribute__((constructor))
static void MTInit(void) {
    @autoreleasepool {
        NSLog(@"[SPOOF] loaded into %@ v%@",
              [[NSBundle mainBundle] bundleIdentifier],
              [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"]);

        struct mt_rebinding rbs[] = {
            { "SecItemCopyMatching",              (void *)f_CopyMatching,   (void **)&o_CopyMatching },
            { "SecItemAdd",                       (void *)f_ItemAdd,        (void **)&o_ItemAdd },
            { "SecItemUpdate",                    (void *)f_ItemUpdate,     (void **)&o_ItemUpdate },
            { "sysctlbyname",                     (void *)f_sysctlbyname,   (void **)&o_sysctlbyname },
            { "uname",                            (void *)f_uname,          (void **)&o_uname },
            { "getenv",                           (void *)f_getenv,         (void **)&o_getenv },
            { "ptrace",                           (void *)f_ptrace,         (void **)&o_ptrace },
            { "CNCopyCurrentNetworkInfo",         (void *)f_CNCopy,         (void **)&o_CNCopy },
            { "CFNetworkCopySystemProxySettings", (void *)f_ProxySettings,  (void **)&o_ProxySettings },
            { "dyld_get_image_name",              (void *)f_imgname,        (void **)&o_imgname },
        };
        int rc = mt_prepend(&g_rebindings, rbs, sizeof(rbs) / sizeof(rbs[0]));
        if (rc == 0) mt_rebind_all(g_rebindings);
        NSLog(@"[SPOOF] fishhook rc=%d  CopyMatching=%@ sysctl=%@ getenv=%@ ptrace=%@",
              rc,
              o_CopyMatching ? @"y" : @"n",
              o_sysctlbyname ? @"y" : @"n",
              o_getenv ? @"y" : @"n",
              o_ptrace ? @"y" : @"n");

        MTSetupHooks();

        MTDump("SAKGuardDeviceFingerprint");
        MTDump("ONIKeychainStorage");
        MTDump("CIPKeychainHelper");
        MTDump("CIPPSSensorRecorder");

        MTProfile *p = [MTProfile shared];
        NSLog(@"[SPOOF] uuid=%@ dpid=%@ bssid=%@", p.uuid, p.dpid, p.bssid);
    }
}
