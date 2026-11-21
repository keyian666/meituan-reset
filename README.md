# meituan-reset

对 **美团 iOS（`com.meituan.imeituan` 12.69.201）** 做设备信息接管，让它被服务端视为"一台新设备"。

面向 **TrollStore（巨魔）+ 无越狱**（iOS 14–17）：产物是独立 `dylib`，用 **TrollFools** 注入，不需要越狱、不需要重签名。

---

## 一、为什么要这么做（逆向后的事实）

二进制已脱壳（`LC_ENCRYPTION_INFO.cryptid = 0`，215 MB，单二进制无独立 Framework）。
`__objc_classlist` / `__objc_methname` 可读，敏感 API 全部套了一层 `CIPPrivacySniffe` 分类 ——
说明美团有统一的隐私采集层，**hook 原始 API 即可全覆盖**。

### 身份链（最关键）

| 层 | 位置 | 卸载是否保留 |
|---|---|---|
| Keychain | group `FSS9ANCQ68.com.meituan.access`，account `com.meituan.kONIPrivateKeychainValue{UUID,DPID,UnionID}` + `kONIShared*` | **保留** |
| IDFV | `identifierForVendor`（`CIPPSIDFVService` / `MTDX_IDFV_Store_Key`） | 重装会变 |
| IDFA | `advertisingIdentifier`（`CIPPSIDFAService`） | 用户可重置 |
| 硬件指纹 | `SAKGuardDeviceFingerprint` / `MSIRiskControlFingerprintContext` / `QCSFingerprintGenerator` | 不变 |

### 陷阱：它记录"你删过 keychain"

```
{"date":"%s","launch_id":"%s","exit_type":"%s","delete_keychain":%d}
{"date":"%s","launch_id":"%s","delete_keychain":%d,"has_delete_keychain":%lf,"old_uuid":"%s"}
```

`CIPLaunchProtectDeleteKeyChain` 会把 `delete_keychain` 状态和 `old_uuid` 一起上报。
**直接清 keychain = 主动告诉风控"我在换设备"**，比不动更糟。

正确做法：**读和写都接管**，让它看到一套"稳定、格式正常、全新"的值。

---

## 二、覆盖清单

### 已接管（改成稳定伪值）

| 类别 | Hook 点 | 处理 |
|---|---|---|
| 设备标识 | `UIDevice.identifierForVendor` | 伪 UUID（持久化） |
| | `ASIdentifierManager.advertisingIdentifier` | 伪 UUID |
| | `UIDevice.name` | 固定 `iPhone`（真值常含姓名） |
| Keychain | `SecItemCopyMatching` / `SecItemAdd` / `SecItemUpdate` | UUID / DPID / UnionID 三键读写接管 |
| 硬件 | `sysctlbyname`（`hw.memsize` / `hw.ncpu` / `hw.physicalcpu` / `hw.logicalcpu` / `hw.pagesize`） | 4GB / 6 核 / 16K |
| | `uname` | 内核版本串固定 |
| 网络 | `CNCopyCurrentNetworkInfo` | 伪 SSID + 伪 BSSID |
| | `NEHotspotNetwork.SSID / BSSID` | 同上 |
| | `CTCarrier.carrierName / mcc / mnc / iso` | 中国移动 460/00/cn |
| | `CFNetworkCopySystemProxySettings` | 返回空（无代理） |
| 存储内存 | `NSFileManager.attributesOfFileSystemForPath:error:` | 128GB / 32GB 可用 |
| | `NSProcessInfo.physicalMemory / processorCount` | 4GB / 6 |
| 电池 | `UIDevice.batteryLevel / batteryState` | 稳定中位值 + Unplugged |
| 剪贴板 | `UIPasteboard.string / strings / items / changeCount` | 空（防止采集复制过的手机号/地址） |
| 已装应用 | `UIApplication.canOpenURL:` | 屏蔽 cydia/sileo/filza/trollstore/frida/竞品 App 等 scheme |
| | `LSApplicationWorkspace.allInstalledApplications` | 只返回 `com.apple.*` |
| 越狱 | `NSFileManager.fileExistsAtPath:` | Cydia / Sileo / Substrate / libhooker / `/var/jb` / TrollStore 标记 → NO |
| 注入痕迹 | `getenv("DYLD_INSERT_LIBRARIES")` | NULL |
| | `_dyld_get_image_name` | 剔除自身与 Substrate |
| 反调试 | `ptrace(request == PT_DENY_ATTACH)` | 直接放行 |
| 标记刷白 | `NSUserDefaults` 的 `delete_keychain` / `hasDeleteKeychain` | NO / 0 |
| 传感器 | `CMMotionManager.is*Available` | NO（`CIPPSSensorRecorder` 靠加速度计做行为指纹） |

### 故意不改（改了反而露馅）

| 项 | 原因 |
|---|---|
| `hw.machine`（机型） | 机型与**屏幕物理分辨率**强绑定。只改机型不改分辨率，交叉校验立刻命中；两者都改会导致 UI 布局错乱 |
| `UIScreen.bounds` / `nativeBounds` / `scale` | 改动会破坏渲染，且同型号设备本来就共享这些值，不构成个体识别 |
| `NSLocale` / `NSTimeZone` / `preferredLanguages` | 与账号收货地址、地理位置强相关，改了反而制造"设备与账号地理矛盾" |
| 真实 IP | 属于网络层，改不了实际连接；且服务端看的是出口 IP |

> 结论：**"能区分个体"的字段全部接管；"型号级"的字段保持真实。** 这是不容易被交叉校验打穿的分界线。

---

## 三、构建

### GitHub Actions

推代码 → `Actions → build-dylib → Artifacts → MTDeviceSpoof-dylib`。

构建日志里会打印 `--- looking for libsubstrate ---`，确认 `$THEOS/vendor/lib/libsubstrate.a` 存在。
找不到就改用 ElleKit，或把 `%hookf` 部分换成内联 fishhook。

### 本地（macOS）

```bash
export THEOS=~/theos
make clean && make
find .theos -name MTDeviceSpoof.dylib -exec cp {} . \;
```

---

## 四、注入（TrollStore / TrollFools）

1. 确保已砸壳（本包 `cryptid=0`，已确认）
2. **TrollFools** → 选择「美团」→ `Inject` → 选 `MTDeviceSpoof.dylib`
3. 重启美团

TrollFools 注入后保留原 bundle id 与 entitlements，所以
`FSS9ANCQ68.com.meituan.access` 这个 keychain group **依然可读** —— 这是能覆盖它的前提。

> 原包 entitlements 已核实：
> ```
> application-identifier = FSS9ANCQ68.com.meituan.imeituan
> keychain-access-groups = FSS9ANCQ68.com.meituan.access
>                          FSS9ANCQ68.com.meituan.imeituan
> application-groups     = group.com.meituan.imeituan
> ```

### 备选：重打包

```bash
ldid -e imeituan > ent.plist
insert_dylib --inplace --strip-codesig \
  @executable_path/Frameworks/MTDeviceSpoof.dylib imeituan
mkdir -p Frameworks && cp MTDeviceSpoof.dylib Frameworks/
ldid -S'ent.plist' imeituan
ldid -S Frameworks/MTDeviceSpoof.dylib
zip -qr mt-spoof.ipa Payload/
```

---

## 五、验证

Mac 连手机开 **Console.app**，过滤 `SPOOF`：

```
[SPOOF] active in com.meituan.imeituan v12.69.201
[SPOOF] profile loaded (0 keys) path=.../Library/Preferences/com.mt.spoof.plist
[SPOOF] uuid=... dpid=... bssid=...
[SPOOF] -[SAKGuardDeviceFingerprint ...]     <- 下一版据此精确 hook
```

确认落盘（Filza 或 `scp`）：

```bash
cat /var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.mt.spoof.plist
```

---

## 六、换一台"新设备"

删掉沙盒内 `Library/Preferences/com.mt.spoof.plist`，重启美团，一整套会重新生成
（UUID / IDFV / IDFA / DPID / UnionID / SSID / BSSID 全换）。

---

## 七、剩下的盲区（下一版）

1. **`SAKGuardDeviceFingerprint` 的硬件指纹**：方法名未定，当前透传原值 —— 这是最大缺口。
2. **`mtgsig`**：native 计算，签名本身改不了；只能改喂给它的采集值。
3. **代码签名校验**：注入后二进制被改，若出现"环境异常"（而非"风险过高"），要额外处理签名校验（`sakguard_static_risk_*`）。
4. **账号维度**：服务端记录了账号历史，设备伪装只解决设备这一维。
