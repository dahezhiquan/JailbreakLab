import Foundation

struct InstalledApplication: Codable, Hashable, Identifiable, Sendable {
    let bundleIdentifier: String
    let displayName: String
    let bundleName: String
    let executableName: String

    var id: String { bundleIdentifier }

    var isValidInjectionTarget: Bool {
        Self.isValidBundleIdentifier(bundleIdentifier) &&
            Self.isValidPathComponent(bundleName, requiresAppExtension: true) &&
            Self.isValidPathComponent(executableName, requiresAppExtension: false) &&
            bundleIdentifier != "com.securitylab.jailbreaklab"
    }

    private static func isValidBundleIdentifier(_ value: String) -> Bool {
        guard value.utf8.count >= 3, value.utf8.count < 256,
              value.first != ".", value.last != ".", value.contains(".") else {
            return false
        }
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-"))
        return value.unicodeScalars.allSatisfy(allowed.contains)
    }

    private static func isValidPathComponent(
        _ value: String,
        requiresAppExtension: Bool
    ) -> Bool {
        guard !value.isEmpty, value.utf8.count < 256,
              value != ".", value != "..",
              !value.contains("/"), !value.contains("\\"),
              value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            return false
        }
        return !requiresAppExtension || value.hasSuffix(".app")
    }
}

enum InstalledApplicationCatalog {
    private static let maximumInfoPlistSize = 1_048_576

    static func load() -> [InstalledApplication] {
        let fileManager = FileManager.default
        let roots = [
            URL(fileURLWithPath: "/private/var/containers/Bundle/Application", isDirectory: true),
            URL(fileURLWithPath: "/var/containers/Bundle/Application", isDirectory: true)
        ]
        var applicationsByIdentifier: [String: InstalledApplication] = [:]

        for root in roots {
            guard let containers = try? fileManager.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
                options: [.skipsHiddenFiles]
            ) else {
                continue
            }
            for container in containers {
                guard isDirectoryWithoutFollowingSymlinks(container) else { continue }
                guard let bundles = try? fileManager.contentsOfDirectory(
                    at: container,
                    includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
                    options: [.skipsHiddenFiles]
                ) else {
                    continue
                }
                for bundleURL in bundles where bundleURL.pathExtension == "app" {
                    guard let application = application(at: bundleURL) else { continue }
                    applicationsByIdentifier[application.bundleIdentifier] = application
                }
            }
            if !applicationsByIdentifier.isEmpty { break }
        }

        return applicationsByIdentifier.values.sorted {
            let comparison = $0.displayName.localizedStandardCompare($1.displayName)
            return comparison == .orderedSame
                ? $0.bundleIdentifier < $1.bundleIdentifier
                : comparison == .orderedAscending
        }
    }

    private static func application(at bundleURL: URL) -> InstalledApplication? {
        guard isDirectoryWithoutFollowingSymlinks(bundleURL) else { return nil }
        let infoURL = bundleURL.appendingPathComponent("Info.plist", isDirectory: false)
        guard let values = try? infoURL.resourceValues(
            forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey]
        ), values.isRegularFile == true, values.isSymbolicLink != true,
              let size = values.fileSize, size > 0, size <= maximumInfoPlistSize,
              let data = try? Data(contentsOf: infoURL, options: [.mappedIfSafe]),
              let object = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let info = object as? [String: Any],
              let bundleIdentifier = info["CFBundleIdentifier"] as? String,
              let executableName = info["CFBundleExecutable"] as? String else {
            return nil
        }

        let fallbackName = info["CFBundleName"] as? String
        let rawDisplayName = (info["CFBundleDisplayName"] as? String) ??
            fallbackName ?? bundleIdentifier
        let displayName = rawDisplayName
            .components(separatedBy: .controlCharacters)
            .joined(separator: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let application = InstalledApplication(
            bundleIdentifier: bundleIdentifier,
            displayName: displayName.isEmpty ? bundleIdentifier : displayName,
            bundleName: bundleURL.lastPathComponent,
            executableName: executableName
        )
        return application.isValidInjectionTarget ? application : nil
    }

    private static func isDirectoryWithoutFollowingSymlinks(_ url: URL) -> Bool {
        guard let values = try? url.resourceValues(
            forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        ) else {
            return false
        }
        return values.isDirectory == true && values.isSymbolicLink != true
    }
}
