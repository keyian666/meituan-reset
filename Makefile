TARGET := iphone:clang:latest:14.0
ARCHS  := arm64
INSTALL_TARGET_PROCESSES := imeituan

TWEAK_NAME := MTDeviceSpoof
MTDeviceSpoof_FILES := Tweak.xm

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

MTDeviceSpoof_CFLAGS := -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable

include $(THEOS)/makefiles/common.mk

# ---------------------------------------------------------------
# hook 引擎必须【静态】链接。
# TrollStore 设备上没有 /Library/Frameworks/CydiaSubstrate.framework，
# 一旦动态依赖它，dylib 加载即失败、App 直接崩。
# 用 -lsubstrate 时链接器会优先选 libsubstrate.dylib，所以显式指向 .a。
# 判断放在 common.mk 之后，此时 $(THEOS) 一定已就绪。
# ---------------------------------------------------------------
SUBSTRATE_A := $(THEOS)/vendor/lib/libsubstrate.a

ifeq ($(wildcard $(SUBSTRATE_A)),)
$(warning [MTDeviceSpoof] libsubstrate.a NOT found -> fallback to dynamic -lsubstrate)
MTDeviceSpoof_LIBRARIES := substrate
MTDeviceSpoof_LDFLAGS := -L$(THEOS)/vendor/lib
else
$(info [MTDeviceSpoof] static substrate: $(SUBSTRATE_A))
MTDeviceSpoof_LDFLAGS := $(SUBSTRATE_A)
endif

include $(THEOS_MAKE_PATH)/tweak.mk
