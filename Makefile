TARGET := iphone:clang:latest:15.0
ARCHS  := arm64
INSTALL_TARGET_PROCESSES := imeituan

# 编成独立 dylib，供 TrollFools / TrollStore 注入（不是 deb 插件）
TWEAK_NAME := MTDeviceSpoof
MTDeviceSpoof_FILES := Tweak.xm
MTDeviceSpoof_FRAMEWORKS := Foundation UIKit Security AdSupport
MTDeviceSpoof_CFLAGS := -fobjc-arc -Wno-deprecated-declarations

# 静态链接 hook 引擎：TrollStore 环境没有 Cydia Substrate，
# 必须把 substrate 的实现打进 dylib，否则 %hook 全部无效。
MTDeviceSpoof_LIBRARIES := substrate
MTDeviceSpoof_LDFLAGS := -L$(THEOS)/vendor/lib

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
