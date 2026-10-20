import Foundation

enum EnvironmentStrategy: String, CaseIterable, Codable, Identifiable, Sendable {
    case jailbreakMarkers = "jailbreak-markers"
    case packageManagers = "package-managers"
    case injectionFrameworks = "injection-frameworks"
    case bypassTools = "bypass-tools"
    case remoteShell = "remote-shell"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .jailbreakMarkers: "越狱标记"
        case .packageManagers: "包管理器"
        case .injectionFrameworks: "注入框架"
        case .bypassTools: "绕过工具"
        case .remoteShell: "Shell / SSH"
        }
    }

    var subtitle: String {
        switch self {
        case .jailbreakMarkers: "bootstrap、jailbreakd 与状态标记"
        case .packageManagers: "APT、Cydia、Sileo、Zebra 目录"
        case .injectionFrameworks: "Substrate、Substitute、Frida 与 tweak 路径"
        case .bypassTools: "Shadow、A-Bypass、FlyJB 等痕迹"
        case .remoteShell: "普通 App 不应可见的命令与配置"
        }
    }

    var symbol: String {
        switch self {
        case .jailbreakMarkers: "checkmark.seal"
        case .packageManagers: "shippingbox"
        case .injectionFrameworks: "cross.vial"
        case .bypassTools: "eye.slash"
        case .remoteShell: "terminal"
        }
    }
}

enum ArtifactKind: String, Codable, Sendable {
    case markerFile = "file"
    case markerDirectory = "directory"
    case probeOnly = "probe-only"

    var label: String {
        switch self {
        case .markerFile: "可创建文件"
        case .markerDirectory: "可创建目录"
        case .probeOnly: "仅探测"
        }
    }
}

struct DetectionArtifact: Identifiable, Hashable, Sendable {
    let path: String
    let strategy: EnvironmentStrategy
    let kind: ArtifactKind

    var id: String { path }
}

enum ArtifactCatalog {
    static let all: [DetectionArtifact] = [
        .init(path: "/var/mobile/Library/Preferences/ABPattern", strategy: .jailbreakMarkers, kind: .markerFile),
        .init(path: "/usr/lib/ABDYLD.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/usr/lib/ABSubLoader.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/usr/sbin/frida-server", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/etc/apt/sources.list.d/electra.list", strategy: .packageManagers, kind: .markerFile),
        .init(path: "/etc/apt/sources.list.d/sileo.sources", strategy: .packageManagers, kind: .markerFile),
        .init(path: "/.bootstrapped_electra", strategy: .jailbreakMarkers, kind: .markerFile),
        .init(path: "/usr/lib/libjailbreak.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/jb/lzma", strategy: .jailbreakMarkers, kind: .markerFile),
        .init(path: "/.cydia_no_stash", strategy: .jailbreakMarkers, kind: .markerFile),
        .init(path: "/.installed_unc0ver", strategy: .jailbreakMarkers, kind: .markerFile),
        .init(path: "/jb/offsets.plist", strategy: .jailbreakMarkers, kind: .markerFile),
        .init(path: "/usr/share/jailbreak/injectme.plist", strategy: .jailbreakMarkers, kind: .markerFile),
        .init(path: "/etc/apt/undecimus/undecimus.list", strategy: .packageManagers, kind: .markerFile),
        .init(path: "/var/lib/dpkg/info/mobilesubstrate.md5sums", strategy: .packageManagers, kind: .markerFile),
        .init(path: "/Library/MobileSubstrate/MobileSubstrate.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/jb/jailbreakd.plist", strategy: .jailbreakMarkers, kind: .markerFile),
        .init(path: "/jb/amfid_payload.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/jb/libjailbreak.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/usr/libexec/cydia/firmware.sh", strategy: .packageManagers, kind: .probeOnly),
        .init(path: "/var/lib/cydia", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/etc/apt", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/private/var/lib/apt", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/var/log/apt", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/Applications/Cydia.app", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/private/var/stash", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/private/var/lib/cydia", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/private/var/cache/apt", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/private/var/log/syslog", strategy: .jailbreakMarkers, kind: .probeOnly),
        .init(path: "/private/var/tmp/cydia.log", strategy: .packageManagers, kind: .markerFile),
        .init(path: "/Applications/Icy.app", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/Applications/MxTube.app", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/Applications/RockApp.app", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/Applications/blackra1n.app", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/Applications/SBSettings.app", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/Applications/FakeCarrier.app", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/Applications/WinterBoard.app", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/Applications/IntelliScreen.app", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/private/var/mobile/Library/SBSettings/Themes", strategy: .jailbreakMarkers, kind: .markerDirectory),
        .init(path: "/Library/MobileSubstrate/CydiaSubstrate.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/System/Library/LaunchDaemons/com.ikey.bbot.plist", strategy: .jailbreakMarkers, kind: .probeOnly),
        .init(path: "/Library/MobileSubstrate/DynamicLibraries/Veency.plist", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist", strategy: .packageManagers, kind: .probeOnly),
        .init(path: "/Applications/Sileo.app", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/var/binpack", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/Library/PreferenceBundles/LibertyPref.bundle", strategy: .bypassTools, kind: .markerDirectory),
        .init(path: "/Library/PreferenceBundles/ShadowPreferences.bundle", strategy: .bypassTools, kind: .markerDirectory),
        .init(path: "/Library/PreferenceBundles/ABypassPrefs.bundle", strategy: .bypassTools, kind: .markerDirectory),
        .init(path: "/Library/PreferenceBundles/FlyJBPrefs.bundle", strategy: .bypassTools, kind: .markerDirectory),
        .init(path: "/Library/PreferenceBundles/Cephei.bundle", strategy: .bypassTools, kind: .markerDirectory),
        .init(path: "/Library/PreferenceBundles/SubstitutePrefs.bundle", strategy: .injectionFrameworks, kind: .markerDirectory),
        .init(path: "/Library/PreferenceBundles/libhbangprefs.bundle", strategy: .injectionFrameworks, kind: .markerDirectory),
        .init(path: "/usr/lib/libhooker.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/usr/lib/libsubstitute.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/usr/lib/substrate", strategy: .injectionFrameworks, kind: .markerDirectory),
        .init(path: "/usr/lib/TweakInject", strategy: .injectionFrameworks, kind: .markerDirectory),
        .init(path: "/var/binpack/Applications/loader.app", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/Applications/FlyJB.app", strategy: .bypassTools, kind: .markerDirectory),
        .init(path: "/Applications/Zebra.app", strategy: .packageManagers, kind: .markerDirectory),
        .init(path: "/Library/BawAppie/ABypass", strategy: .bypassTools, kind: .markerDirectory),
        .init(path: "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.plist", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.plist", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib", strategy: .injectionFrameworks, kind: .probeOnly),
        .init(path: "/Library/MobileSubstrate/DynamicLibraries", strategy: .injectionFrameworks, kind: .markerDirectory),
        .init(path: "/var/mobile/Library/Preferences/me.jjolano.shadow.plist", strategy: .bypassTools, kind: .markerFile),
        .init(path: "/bin/bash", strategy: .remoteShell, kind: .probeOnly),
        .init(path: "/usr/sbin/sshd", strategy: .remoteShell, kind: .probeOnly),
        .init(path: "/usr/libexec/ssh-keysign", strategy: .remoteShell, kind: .probeOnly),
        .init(path: "/bin/sh", strategy: .remoteShell, kind: .probeOnly),
        .init(path: "/etc/ssh/sshd_config", strategy: .remoteShell, kind: .probeOnly),
        .init(path: "/usr/libexec/sftp-server", strategy: .remoteShell, kind: .probeOnly),
        .init(path: "/usr/bin/ssh", strategy: .remoteShell, kind: .probeOnly)
    ]
}

enum OperationMode: String, CaseIterable, Identifiable, Sendable {
    case dryRun
    case live

    var id: String { rawValue }
    var title: String { self == .dryRun ? "预演" : "真实写入" }
}

enum RootLayout: String, CaseIterable, Identifiable, Sendable {
    case automatic = "auto"
    case rootful
    case rootless

    var id: String { rawValue }
    var title: String {
        switch self {
        case .automatic: "自动"
        case .rootful: "Rootful"
        case .rootless: "Rootless"
        }
    }
}

enum ArtifactStatus: String, Codable, Sendable {
    case planned
    case created
    case alreadyPresent = "already_present"
    case absent
    case removed
    case probeOnly = "probe_only"
    case protected
    case failed

    var title: String {
        switch self {
        case .planned: "待创建"
        case .created: "已创建"
        case .alreadyPresent: "已存在"
        case .absent: "不存在"
        case .removed: "已清理"
        case .probeOnly: "仅探测"
        case .protected: "已保护"
        case .failed: "失败"
        }
    }
}

struct ArtifactResult: Codable, Identifiable, Hashable, Sendable {
    let path: String
    let effectivePath: String
    let status: ArtifactStatus
    let message: String

    var id: String { path }
}
