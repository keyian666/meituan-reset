// MTDeviceSpoof — 中等版：最小功能 + bundle 身份伪装
// 目标: com.meituan.imeituan1（多开版）伪装成 com.meituan.imeituan
// 环境: TrollStore + TrollFools，无越狱、无 substrate
//
// 伪装面：
//   1. NSBundle.bundleIdentifier / infoDictionary
//   2. SecTaskCopyValueForEntitlement（application-identifier / keychain-access-groups）
//   3. _NSGetExecutablePath / proc_pidpath（路径里的 imeituan1.app）
//   4. NSProcessInfo.processName / arguments
//   5. IDFV / IDFA / keychain UUID/DPID
//
// 刻意不改：NSBundle.bundlePath / resourcePath / executablePath
//   —— 这些被 App 自己用于读资源，改了会读不到文件

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <string.h>
#import <unistd.h>
#import <stdlib.h>
#import <mach-o/dyld.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// SecTask 是私有 API，手动声明避免头文件缺失
typedef struct __SecTask *SecTaskRef;
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef task, CFStringRef entitlement, CFErrorRef *error);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
extern int _NSGetExecutablePath(char *buf, uint32_t *bufsize);

#pragma mark - ===================== 身份常量 =====================

static NSString *g_realBundleId = nil;      // 例: com.meituan.imeituan1
static NSString *g_fakeBundleId = nil;      // 例: com.meituan.imeituan
static char g_realAppDirC[256] = {0};       // 例: imeituan1.app
static char g_fakeAppDirC[256] = {0};       // 例: imeituan.app

static void MTInitIdentityConstants(void) {
    // 用 CF 而不是 NSBundle：constructor 阶段更安全
    CFBundleRef mb = CFBundleGetMainBundle();
    CFStringRef bid = mb ? CFBundleGetIdentifier(mb) : NULL;
    g_realBundleId = bid ? (__bridge_transfer NSString *)CFStringCreateCopy(NULL, bid) : @"";

    NSString *fake = g_realBundleId;
    if ([fake hasSuffix:@"1"]) fake = [fake substringToIndex:fake.length - 1];
    g_fakeBundleId = [fake copy];

    // 从可执行文件真实路径里取 ".app" 目录名（纯 C，不经过 NSBundle）
    char path[4096]; uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, &sz) == 0) {
        char *appExt = strstr(path, ".app/");
        if (appExt) {
            char *start = appExt;
            while (start > path && *(start - 1) != '/') start--;
            size_t len = (size_t)(appExt - start) + 4;   // 含 ".app"
            if (len < sizeof(g_realAppDirC)) {
                memcpy(g_realAppDirC, start, len);
                g_realAppDirC[len] = '\0';
                strncpy(g_fakeAppDirC, g_realAppDirC, sizeof(g_fakeAppDirC) - 1);
                char *one = strstr(g_fakeAppDirC, "1.app");
                if (one) memmove(one, one + 1, strlen(one + 1) + 1);
            }
        }
    }
}

#pragma mark - ===================== fishhook =====================

struct mt_rebinding { const char *name; void *replacement; void **replaced; };
static struct mt_rebinding g_rbs[16];
static size_t g_rb_count = 0;

static void mt_rebind_image(const struct mach_header_64 *hdr, intptr_t slide) {
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;
    const struct segment_command_64 *linkedit = NULL;

    uintptr_t cur = (uintptr_t)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SYMTAB)   symtab   = (const struct symtab_command *)lc;
        if (lc->cmd == LC_DYSYMTAB) dysymtab = (const struct dysymtab_command *)lc;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *s = (const struct segment_command_64 *)lc;
            if (strcmp(s->segname, "__LINKEDIT") == 0) linkedit = s;
        }
        cur += lc->cmdsize;
    }
    if (!symtab || !dysymtab || !linkedit) return;

    // offset 是文件偏移，必须经 __LINKEDIT 换算（hdr+offset 会越界）
    uintptr_t le_base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    const struct nlist_64 *syms = (const struct nlist_64 *)(le_base + symtab->symoff);
    const char *strtab = (const char *)(le_base + symtab->stroff);
    const uint32_t *indirect = (const uint32_t *)(le_base + dysymtab->indirectsymoff);

    cur = (uintptr_t)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__DATA") != 0 &&
                strcmp(seg->segname, "__DATA_CONST") != 0) { cur += lc->cmdsize; continue; }

            for (uint32_t j = 0; j < seg->nsects; j++) {
                const struct section_64 *sect =
                    (const struct section_64 *)((uintptr_t)seg + sizeof(*seg) + j * sizeof(*sect));
                uint32_t t = sect->flags & SECTION_TYPE;
                if (t != S_LAZY_SYMBOL_POINTERS && t != S_NON_LAZY_SYMBOL_POINTERS) continue;
                if (sect->size == 0) continue;

                uintptr_t *slots = (uintptr_t *)(uintptr_t)(slide + sect->addr);
                size_t n = sect->size / sizeof(uintptr_t);

                uintptr_t pg = (uintptr_t)getpagesize();
                uintptr_t start = (uintptr_t)slots & ~(pg - 1);
                uintptr_t end = ((uintptr_t)slots + sect->size + pg - 1) & ~(pg - 1);
                if (vm_protect(mach_task_self(), (vm_address_t)start, end - start, false,
                               VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) continue;

                for (size_t k = 0; k < n; k++) {
                    uint32_t idx = indirect[sect->reserved1 + k];
                    if (idx == INDIRECT_SYMBOL_LOCAL || idx == INDIRECT_SYMBOL_ABS) continue;
                    if (idx >= symtab->nsyms) continue;
                    const char *nm = strtab + syms[idx].n_un.n_strx;
                    if (!nm || !nm[0]) continue;
                    if (nm[0] == '_') nm++;
                    for (size_t r = 0; r < g_rb_count; r++) {
                        if (g_rbs[r].name && strcmp(g_rbs[r].name, nm) == 0) {
                            if (g_rbs[r].replaced && !*g_rbs[r].replaced)
                                *g_rbs[r].replaced = (void *)slots[k];
                            slots[k] = (uintptr_t)g_rbs[r].replacement;
                        }
                    }
                }
                vm_protect(mach_task_self(), (vm_address_t)start, end - start, false,
                           VM_PROT_READ | VM_PROT_EXECUTE);
            }
        }
        cur += lc->cmdsize;
    }
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
    });
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
- (NSString *)dpid    { return [self val:@"dpid"    gen:^id{ return [NSUUID UUID].UUIDString; }]; }
@end

static NSString *MTSpoofForKey(id acct) {
    if (![acct isKindOfClass:[NSString class]]) return nil;
    NSString *s = (NSString *)acct;
    MTProfile *p = [MTProfile shared];
    if ([s rangeOfString:@"KeychainValueUUID"].location != NSNotFound) return p.uuid;
    if ([s rangeOfString:@"KeychainValueDPID"].location != NSNotFound) return p.dpid;
    return nil;
}

#pragma mark - ===================== C 函数实现 =====================

static OSStatus (*o_CopyMatching)(CFDictionaryRef, CFTypeRef *);
static CFTypeRef (*o_SecTaskCopyEnt)(SecTaskRef, CFStringRef, CFErrorRef *);
static int (*o_GetExePath)(char *, uint32_t *);
static int (*o_proc_pidpath)(int, void *, uint32_t);

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

// entitlements：让 SDK 读到原版 identity（不调用原函数，避免泄漏与副作用）
static CFTypeRef f_SecTaskCopyEnt(SecTaskRef task, CFStringRef key, CFErrorRef *err) {
    if (key) {
        if (CFStringCompare(key, CFSTR("application-identifier"), 0) == kCFCompareEqualTo) {
            NSString *v = [NSString stringWithFormat:@"FSS9ANCQ68.%@", g_fakeBundleId];
            return CFBridgingRetain(v);
        }
        if (CFStringCompare(key, CFSTR("keychain-access-groups"), 0) == kCFCompareEqualTo) {
            NSArray *groups = @[
                @"FSS9ANCQ68.com.meituan.access",
                [NSString stringWithFormat:@"FSS9ANCQ68.%@", g_fakeBundleId],
            ];
            return CFBridgingRetain(groups);
        }
    }
    return o_SecTaskCopyEnt ? o_SecTaskCopyEnt(task, key, err) : NULL;
}

// 可执行路径：imeituan1.app -> imeituan.app（纯 C，不碰 ObjC）
static void MTPatchPath(char *buf) {
    if (!buf || !g_realAppDirC[0] || !g_fakeAppDirC[0]) return;
    char *p = strstr(buf, g_realAppDirC);
    if (!p) return;
    size_t from = strlen(g_realAppDirC);
    size_t to   = strlen(g_fakeAppDirC);
    if (to >= from) return;
    memmove(p + to, p + from, strlen(p + from) + 1);
}

static int f_GetExePath(char *buf, uint32_t *bufsize) {
    int r = o_GetExePath ? o_GetExePath(buf, bufsize) : -1;
    if (r == 0) MTPatchPath(buf);
    return r;
}

static int f_proc_pidpath(int pid, void *buffer, uint32_t buffersize) {
    int r = o_proc_pidpath ? o_proc_pidpath(pid, buffer, buffersize) : -1;
    if (r > 0) MTPatchPath((char *)buffer);
    return r;
}

#pragma mark - ===================== ObjC hook =====================

static IMP o_bundleId, o_infoDict, o_procName, o_args;

static void mt_hook(Class cls, SEL sel, id block, IMP *orig) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (orig) *orig = method_getImplementation(m);
    method_setImplementation(m, imp_implementationWithBlock(block));
}

static void MTSetupHooks(void) {
    MTProfile *P = [MTProfile shared];
    Class NSBundleCls = [NSBundle class];

    // ---- bundleIdentifier ----
    mt_hook(NSBundleCls, @selector(bundleIdentifier), ^NSString *(id self) {
        NSString *(*f)(id, SEL) = (void *)o_bundleId;
        NSString *real = f ? f(self, @selector(bundleIdentifier)) : nil;
        if (g_realBundleId.length && [real isEqualToString:g_realBundleId]) return g_fakeBundleId;
        return real;
    }, &o_bundleId);

    // ---- infoDictionary（只改副本，不动真实字典）----
    mt_hook(NSBundleCls, @selector(infoDictionary), ^NSDictionary *(id self) {
        NSDictionary *(*f)(id, SEL) = (void *)o_infoDict;
        NSDictionary *d = f ? f(self, @selector(infoDictionary)) : nil;
        if (![d isKindOfClass:[NSDictionary class]]) return d;
        id bid = d[@"CFBundleIdentifier"];
        if (![bid isKindOfClass:[NSString class]] || ![bid isEqualToString:g_realBundleId]) return d;
        NSMutableDictionary *m = [d mutableCopy];
        m[@"CFBundleIdentifier"] = g_fakeBundleId;
        return m;
    }, &o_infoDict);

    // ---- processName / arguments ----
    mt_hook([NSProcessInfo class], @selector(processName), ^NSString *(id self) {
        NSString *(*f)(id, SEL) = (void *)o_procName;
        NSString *n = f ? f(self, @selector(processName)) : nil;
        return n ?: @"imeituan";
    }, &o_procName);

    mt_hook([NSProcessInfo class], @selector(arguments), ^NSArray *(id self) {
        NSArray *(*f)(id, SEL) = (void *)o_args;
        NSArray *a = f ? f(self, @selector(arguments)) : nil;
        if (![a isKindOfClass:[NSArray class]] || a.count == 0) return a;
        NSMutableArray *m = [a mutableCopy];
        NSString *first = m.firstObject;
        if ([first isKindOfClass:[NSString class]]) {
            char tmp[4096]; memset(tmp, 0, sizeof(tmp));
            strncpy(tmp, first.UTF8String, sizeof(tmp) - 1);
            MTPatchPath(tmp);
            m[0] = @(tmp);
        }
        return m;
    }, &o_args);

    // ---- 设备标识 ----
    mt_hook([UIDevice class], @selector(identifierForVendor), ^NSUUID *(id self) {
        (void)self; return [[NSUUID alloc] initWithUUIDString:P.idfv];
    }, NULL);

    Class asim = NSClassFromString(@"ASIdentifierManager");
    if (asim) {
        mt_hook(asim, @selector(advertisingIdentifier), ^NSUUID *(id self) {
            (void)self; return [[NSUUID alloc] initWithUUIDString:P.idfa];
        }, NULL);
    }
}

#pragma mark - ===================== entry =====================

__attribute__((constructor))
static void MTInit(void) {
    @autoreleasepool {
        // 必须在任何 hook 之前抓取真实值
        MTInitIdentityConstants();

        NSLog(@"[SPOOF] loaded. realId=%@ -> fakeId=%@ | realDir=%s -> fakeDir=%s",
              g_realBundleId, g_fakeBundleId, g_realAppDirC, g_fakeAppDirC);

        g_rbs[g_rb_count++] = (struct mt_rebinding){ "SecItemCopyMatching",          (void *)f_CopyMatching,   (void **)&o_CopyMatching };
        g_rbs[g_rb_count++] = (struct mt_rebinding){ "SecTaskCopyValueForEntitlement",(void *)f_SecTaskCopyEnt, (void **)&o_SecTaskCopyEnt };
        g_rbs[g_rb_count++] = (struct mt_rebinding){ "_NSGetExecutablePath",         (void *)f_GetExePath,     (void **)&o_GetExePath };
        g_rbs[g_rb_count++] = (struct mt_rebinding){ "proc_pidpath",                 (void *)f_proc_pidpath,   (void **)&o_proc_pidpath };

        const struct mach_header *h = _dyld_get_image_header(0);
        if (h && h->magic == MH_MAGIC_64)
            mt_rebind_image((const struct mach_header_64 *)h, _dyld_get_image_vmaddr_slide(0));

        NSLog(@"[SPOOF] fishhook: CopyMatching=%@ SecTask=%@ ExePath=%@ pidpath=%@",
              o_CopyMatching ? @"y":@"n", o_SecTaskCopyEnt ? @"y":@"n",
              o_GetExePath ? @"y":@"n", o_proc_pidpath ? @"y":@"n");

        MTSetupHooks();

        MTProfile *p = [MTProfile shared];
        NSLog(@"[SPOOF] uuid=%@ dpid=%@", p.uuid, p.dpid);
    }
}
