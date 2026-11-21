# 零依赖 dylib：不链接 CydiaSubstrate / ElleKit / Logos
# 用 library.mk 直接产出 MTDeviceSpoof.dylib（而不是 deb 插件）
TARGET := iphone:clang:latest:14.0
ARCHS  := arm64

TWEAK_NAME := MTDeviceSpoof
MTDeviceSpoof_FILES := Tweak.m

MTDeviceSpoof_FRAMEWORKS := \
	Foundation \
	UIKit \
	Security \
	AdSupport \
	CoreTelephony \
	CoreMotion \
	SystemConfiguration \
	NetworkExtension \
	CFNetwork

MTDeviceSpoof_CFLAGS := -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-function

# 注意：这里【故意】不设置 MTDeviceSpoof_LIBRARIES，
# 否则 Theos 会加 -lsubstrate，而 TrollStore 设备没有 CydiaSubstrate.framework。
# hook 引擎由 Tweak.m 内联的 fishhook + method_setImplementation 提供。
MTDeviceSpoof_LDFLAGS := -Wl,-dead_strip

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/library.mk
