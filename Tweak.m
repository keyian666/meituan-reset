// MTDeviceSpoof — 最小可运行版（排查闪退用）
// 只做三件事：IDFV / IDFA / keychain UUID
// fishhook 只处理主二进制（image 0），不遍历系统库
//
// 如果这个版本能正常启动 -> 说明基础框架 OK，崩溃来自完整版里某个 hook
// 如果这个也崩 -> 问题在 fishhook 或 constructor 时机

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <string.h>
#import <mach-o/dyld.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <stdlib.h>

#pragma mark - fishhook

struct mt_rebinding { const char *name; void *replacement; void **replaced; };
static struct mt_rebinding g_rbs[8];
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

    // 关键：symtab/dysymtab 里的 offset 是【文件偏移】，
    // 必须通过 __LINKEDIT 的 vmaddr/fileoff 换算成运行时地址。
    // 用 hdr + offset 会在主二进制（215MB）上算到未映射区域 -> SIGSEGV。
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
                        if (strcmp(g_rbs[r].name, nm) == 0) {
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

#pragma mark - 伪档案

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
    if ([s rangeOfString:@"KeychainValueUUID"].location    != NSNotFound) return p.uuid;
    if ([s rangeOfString:@"KeychainValueDPID"].location    != NSNotFound) return p.dpid;
    return nil;
}

#pragma mark - keychain hook

static OSStatus (*o_CopyMatching)(CFDictionaryRef, CFTypeRef *);

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

#pragma mark - ObjC hook

static void mt_hook(Class cls, SEL sel, id block) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    method_setImplementation(m, imp_implementationWithBlock(block));
}

#pragma mark - entry

__attribute__((constructor))
static void MTInit(void) {
    @autoreleasepool {
        NSLog(@"[SPOOF] minimal build loaded in %@", [[NSBundle mainBundle] bundleIdentifier]);

        // fishhook: 只挂主二进制
        g_rbs[g_rb_count++] = (struct mt_rebinding){ "SecItemCopyMatching", (void *)f_CopyMatching, (void **)&o_CopyMatching };

        const struct mach_header *h = _dyld_get_image_header(0);
        if (h && h->magic == MH_MAGIC_64) {
            mt_rebind_image((const struct mach_header_64 *)h, _dyld_get_image_vmaddr_slide(0));
        }
        NSLog(@"[SPOOF] fishhook done, o_CopyMatching=%@", o_CopyMatching ? @"y" : @"n");

        MTProfile *P = [MTProfile shared];

        mt_hook([UIDevice class], @selector(identifierForVendor), ^NSUUID *(id self) {
            (void)self; return [[NSUUID alloc] initWithUUIDString:P.idfv];
        });

        Class asim = NSClassFromString(@"ASIdentifierManager");
        if (asim) {
            mt_hook(asim, @selector(advertisingIdentifier), ^NSUUID *(id self) {
                (void)self; return [[NSUUID alloc] initWithUUIDString:P.idfa];
            });
        }

        NSLog(@"[SPOOF] minimal hooks installed, uuid=%@ dpid=%@", P.uuid, P.dpid);
    }
}
