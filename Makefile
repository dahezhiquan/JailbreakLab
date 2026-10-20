SHELL := /bin/zsh
PROJECT := JailbreakLab.xcodeproj
TARGET := JailbreakLab
BUILD_DIR := $(CURDIR)/build
APP := $(BUILD_DIR)/Release-iphoneos/JailbreakLab.app
HELPER := $(BUILD_DIR)/jailbreaklab-helper

.PHONY: project app helper package clean test-helper

project:
	@test -f $(PROJECT)/project.pbxproj || { echo "missing $(PROJECT)"; exit 1; }

app: project
	xcodebuild -project $(PROJECT) -target $(TARGET) -configuration Release -sdk iphoneos -derivedDataPath $(BUILD_DIR)/DerivedData CODE_SIGNING_ALLOWED=NO build
	rm -rf $(APP)
	mkdir -p $(dir $(APP))
	cp -R $(BUILD_DIR)/DerivedData/Build/Products/Release-iphoneos/JailbreakLab.app $(APP)

helper:
	@xcrun --sdk iphoneos --find clang >/dev/null || { echo "Full Xcode with iPhoneOS SDK is required"; exit 1; }
	$$(xcrun --sdk iphoneos --find clang) -arch arm64 -isysroot $$(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=16.0 -Os -Wall -Wextra -Werror Helper/main.c -o $(HELPER)

package: app helper
	./Packaging/package.sh $(APP) $(HELPER)

test-helper:
	./Tests/run_helper_tests.sh

clean:
	rm -rf $(BUILD_DIR) $(PROJECT) Packages
