ARCHS = arm64
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = RobloxProxy
RobloxProxy_FILES = Tweak.x
RobloxProxy_CFLAGS = -fobjc-arc
RobloxProxy_FRAMEWORKS = Foundation CFNetwork

include $(THEOS)/makefiles/tweak.mk
