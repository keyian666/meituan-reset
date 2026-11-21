# meituan-reset

给 **美团 iOS（`com.meituan.imeituan`）** 注入一套稳定、可控的设备身份，让它被服务端视为"一台新设备"。

面向 **TrollStore（巨魔）+ 无越狱**（iOS 14–17），产物是独立 `dylib`，用 **TrollFools** 注入，不需要重签名、不需要电脑。

---

## 为什么不能"删文件了事"

美团 iOS 的设备身份有三层，最顽固的一层在 keychain：

| 层 | 位置 | 卸载后是否保留 |
|---|---|---|
| Keychain | group `FSS9ANCQ68.com.meituan.access`，account `com.meituan.kONIPrivateKeychainValue{UUID,DPID,UnionID}` 及 `kONIShared*` | **保留** |
| IDFV | `identifierForVendor`（`CIPPSIDFVService` / `MTDX_IDFV_Store_Key`） | 重装会变 |
| 硬件指纹 | `SAKGuardDeviceFingerprint` / `MSIRiskControlFingerprintContext` | 不变 |

而且二进制里有这几条格式串：

```
{"date":"%s","launch_id":"%s","exit_type":"%s","delete_keychain":%d}
{"date":"%s","launch_id":"%s","delete_keychain":%d,"has_delete_keychain":%lf,"old_uuid":"%s"}
```

`CIPLaunchProtectDeleteKeyChain` 会记录"你删过 keychain"，并把 `old_uuid` 一起上报 ——
所以**直接清 keychain 是负收益**，比不动更可疑。

正确做法：**读和写都接管**，让它看到一套"看起来正常、稳定、全新"的值。

---

## 本项目的做法

- 生成一套伪身份（UUID / IDFV / IDFA / DPID / UnionID），持久化在 App 沙盒
  `Library/Preferences/com.mt.spoof.plist`
- `SecItemCopyMatching` / `SecItemAdd` / `SecItemUpdate` 三个入口同时改写
- 屏蔽注入痕迹：`DYLD_INSERT_LIBRARIES`、`_dyld_get_image_name` 里的自身镜像
- 屏蔽常见越狱路径探针
- 压掉 `delete_keychain` / `hasDeleteKeychain` 标记
- 首版额外 dump 指纹相关类的方法名，用于下一轮精确 hook

---

## 构建

### GitHub Actions（推荐，仓库已带 workflow）

推代码即可，`Actions → build-dylib → Artifacts` 下载 `MTDeviceSpoof.dylib`。

### 本地（macOS）

```bash
export THEOS=~/theos
make clean && make
find .theos -name MTDeviceSpoof.dylib -exec cp {} . \;
```

> 关键：`Makefile` 里 `MTDeviceSpoof_LIBRARIES := substrate` 把 hook 引擎**静态链进 dylib**。
> TrollStore 环境没有 Cydia Substrate，不静态链接的话 `%hook` 全部失效。
> 如果 Theos 里找不到 `libsubstrate.a`，改用 ElleKit 或自行内联 fishhook。

---

## 注入（TrollStore / TrollFools）

1. 确保已用 **AppDump3 / TrollDecrypt** 砸壳（本二进制 `cryptid=0`，已确认脱壳）
2. 打开 **TrollFools** → 选择「美团」→ `Inject` → 选 `MTDeviceSpoof.dylib`
3. 重启美团

TrollFools 注入后仍保留原 bundle id 与 entitlements，因此
`FSS9ANCQ68.com.meituan.access` 这个 keychain group **依然可读** —— 这是能"覆盖"它的前提。

### 备选：重打包

```bash
ldid -e imeituan > ent.plist            # 提取原 entitlements（必须保留 keychain group）
insert_dylib --inplace --strip-codesig \
  @executable_path/Frameworks/MTDeviceSpoof.dylib imeituan
mkdir -p Frameworks && cp MTDeviceSpoof.dylib Frameworks/
ldid -S'ent.plist' imeituan
ldid -S Frameworks/MTDeviceSpoof.dylib
zip -qr mt-spoof.ipa Payload/
```

然后用 TrollStore 安装（同 bundle id 覆盖安装，App 数据与 keychain 保留）。

---

## 验证

用 **Console.app**（Mac 连手机）或 TrollStore 自带的日志查看，过滤 `SPOOF`：

```
[SPOOF] loaded into com.meituan.imeituan v12.69.201
[SPOOF] store=0 path=/var/mobile/Containers/Data/Application/<UUID>/Library/Preferences/com.mt.spoof.plist
[SPOOF] +deviceFingerprintIdentifier:      <- 下一轮据此精确 hook
[SPOOF] -getFingerprintID
...
```

确认身份落盘：

```bash
# 越狱设备可直接看；TrollStore 无越狱用 Filza 之类浏览该容器
cat /var/mobile/Containers/Data/Application/*/Library/Preferences/com.mt.spoof.plist
```

---

## 换一台"新设备"

删掉沙盒里的 `Library/Preferences/com.mt.spoof.plist`，重启美团，会重新生成一整套。

或者给 TrollFools 的 App 做一次「卸载数据」（注意：清数据也会重置登录态）。

---

## 已知限制

1. `mtgsig` 是 native 计算，签名本身改不了；能改的是喂给它的采集结果 —— 所以 hook 采集点才是正确入口。
2. 美团可能检测代码签名 / 二进制被修改（`sakguard_static_risk_*`）。注入后如果出现"环境异常"，需要额外处理签名校验。
3. 服务端还有账号维度与行为维度，伪装设备只解决"设备"这一维。
4. 首版是"通用 hook"，`SAKGuardDeviceFingerprint` 的真实方法名要靠 dump 结果补上，才能把硬件指纹也替换掉。

---

## 下一步

1. 跑一次，拿到 `[SPOOF]` 的 dump 输出
2. 把 `SAKGuardDeviceFingerprint` / `ONIKeychainStorage` 的真实方法名贴进来
3. 补精确 hook（返回伪值而不是原值）
4. 再验证一次下单链路
