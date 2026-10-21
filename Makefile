SHELL := /bin/zsh
PROJECT := JailbreakLab.xcodeproj
TARGET := JailbreakLab
BUILD_DIR := $(CURDIR)/build
APP := $(BUILD_DIR)/Release-iphoneos/JailbreakLab.app
HELPER := $(BUILD_DIR)/jailbreaklab-helper
INJECTION := $(BUILD_DIR)/JailbreakLabShadow.dylib
RUNTIME_HOOK_INJECTION := $(BUILD_DIR)/JailbreakLabRuntimeHook.dylib

.PHONY: project app helper injection package clean test-helper

project:
	@test -f $(PROJECT)/project.pbxproj || { echo "missing $(PROJECT)"; exit 1; }

app: project
	rm -rf $(APP)
	mkdir -p $(dir $(APP))
	xcodebuild -project $(PROJECT) -target $(TARGET) -configuration Release -sdk iphoneos CONFIGURATION_BUILD_DIR=$(dir $(APP)) CODE_SIGNING_ALLOWED=NO build

helper:
	@xcrun --sdk iphoneos --find clang >/dev/null || { echo "Full Xcode with iPhoneOS SDK is required"; exit 1; }
	$$(xcrun --sdk iphoneos --find clang) -arch arm64 -isysroot $$(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=16.0 -Os -Wall -Wextra -Werror Helper/main.c -o $(HELPER)

injection:
	@xcrun --sdk iphoneos --find clang >/dev/null || { echo "Full Xcode with iPhoneOS SDK is required"; exit 1; }
	mkdir -p $(BUILD_DIR)
	$$(xcrun --sdk iphoneos --find clang) -arch arm64 -isysroot $$(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=16.0 -Os -Wall -Wextra -Werror -dynamiclib -fvisibility=hidden -Wl,-install_name,@rpath/JailbreakLabShadow.dylib -lobjc Injection/ShadowRuntime.m -o $(INJECTION)
	$$(xcrun --sdk iphoneos --find clang) -arch arm64 -isysroot $$(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=16.0 -Os -Wall -Wextra -Werror -dynamiclib -fvisibility=hidden -Wl,-install_name,@rpath/JailbreakLabRuntimeHook.dylib -lobjc Injection/RuntimeHook.m -o $(RUNTIME_HOOK_INJECTION)

package: app helper injection
	./Packaging/package.sh $(APP) $(HELPER) $(INJECTION) $(RUNTIME_HOOK_INJECTION)

test-helper:
	./Tests/run_helper_tests.sh
	clang -fsyntax-only -Wall -Wextra -Werror Injection/ShadowRuntime.m
	clang -fsyntax-only -Wall -Wextra -Werror Injection/RuntimeHook.m

clean:
	rm -rf $(BUILD_DIR) $(PROJECT) Packages
