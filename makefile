TARGET := iphone:clang:latest:12.0
ARCHS  := arm64
TWEAK_NAME := MTDeviceSpoof
MTDeviceSpoof_FILES := Tweak.xm
MTDeviceSpoof_FRAMEWORKS := Foundation UIKit Security AdSupport
include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
