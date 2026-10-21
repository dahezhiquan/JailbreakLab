import Foundation
import Combine

@MainActor
final class SimulationStore: ObservableObject {
    @Published private(set) var isSuspiciousFilesEnabled: Bool
    @Published private(set) var suspiciousFilesStatus: String
    @Published private(set) var isRestrictedWriteEnabled: Bool
    @Published private(set) var restrictedWriteStatus: String
    @Published private(set) var restrictedWriteDetails: [String]
    @Published private(set) var isAbnormalSymlinksEnabled: Bool
    @Published private(set) var abnormalSymlinksStatus: String
    @Published private(set) var abnormalSymlinksDetails: [String]
    @Published private(set) var isSuspiciousObjCClassEnabled: Bool
    @Published private(set) var suspiciousObjCClassStatus: String
    @Published private(set) var installedApplications: [InstalledApplication] = []
    @Published private(set) var selectedApplication: InstalledApplication?
    @Published private(set) var isLoadingApplications = false
    @Published private(set) var results: [ArtifactResult] = []
    @Published private(set) var isRunning = false
    @Published var alertMessage: String?

    private let helperClient: HelperClient
    private let defaults: UserDefaults
    private let applicationLoader: @Sendable () -> [InstalledApplication]
    private static let suspiciousFilesKey = "SuspiciousFilesEnvironmentEnabled"
    private static let restrictedWriteKey = "RestrictedWriteEnvironmentEnabled"
    private static let abnormalSymlinksKey = "AbnormalSymlinksEnvironmentEnabled"
    private static let suspiciousObjCClassKey = "SuspiciousObjCClassEnvironmentEnabled"
    private static let selectedApplicationKey = "SuspiciousObjCClassTargetApplication"

    init(
        defaults: UserDefaults = .standard,
        helperClient: HelperClient = HelperClient(),
        applicationLoader: @escaping @Sendable () -> [InstalledApplication] = {
            InstalledApplicationCatalog.load()
        }
    ) {
        self.defaults = defaults
        self.helperClient = helperClient
        self.applicationLoader = applicationLoader
        let suspiciousFilesEnabled = defaults.bool(forKey: Self.suspiciousFilesKey)
        let restrictedWriteEnabled = defaults.bool(forKey: Self.restrictedWriteKey)
        let abnormalSymlinksEnabled = defaults.bool(forKey: Self.abnormalSymlinksKey)
        var suspiciousObjCClassEnabled = defaults.bool(
            forKey: Self.suspiciousObjCClassKey
        )
        let storedApplication = defaults.data(forKey: Self.selectedApplicationKey)
            .flatMap { try? JSONDecoder().decode(InstalledApplication.self, from: $0) }
            .flatMap { $0.isValidInjectionTarget ? $0 : nil }
        if suspiciousObjCClassEnabled && storedApplication == nil {
            suspiciousObjCClassEnabled = false
            defaults.set(false, forKey: Self.suspiciousObjCClassKey)
        }
        isSuspiciousFilesEnabled = suspiciousFilesEnabled
        suspiciousFilesStatus = suspiciousFilesEnabled ? "已开启" : "已关闭"
        isRestrictedWriteEnabled = restrictedWriteEnabled
        restrictedWriteStatus = restrictedWriteEnabled ? "已开启：等待刷新三个目录状态" : "已关闭"
        restrictedWriteDetails = restrictedWriteEnabled
            ? ["上次已开启；重新切换开关可刷新逐项结果"]
            : []
        isAbnormalSymlinksEnabled = abnormalSymlinksEnabled
        abnormalSymlinksStatus = abnormalSymlinksEnabled
            ? "已开启：等待刷新 7 个路径状态"
            : "已关闭"
        abnormalSymlinksDetails = abnormalSymlinksEnabled
            ? ["上次已开启；重新切换开关可刷新逐项结果"]
            : []
        isSuspiciousObjCClassEnabled = suspiciousObjCClassEnabled
        selectedApplication = storedApplication
        suspiciousObjCClassStatus = suspiciousObjCClassEnabled
            ? "已开启：重新打开\(storedApplication?.displayName ?? "目标 App")后生效"
            : (storedApplication == nil ? "已关闭：请选择检测 App" : "已关闭")
    }

    func refreshInstalledApplications() async {
        guard !isLoadingApplications else { return }
        isLoadingApplications = true
        let loader = applicationLoader
        let applications = await Task.detached(priority: .userInitiated) {
            loader()
        }.value
        installedApplications = applications
        if let selectedApplication,
           let refreshed = applications.first(where: {
               $0.bundleIdentifier == selectedApplication.bundleIdentifier
           }) {
            self.selectedApplication = refreshed
            persistSelectedApplication(refreshed)
        }
        isLoadingApplications = false
    }

    func selectApplication(_ application: InstalledApplication) {
        guard !isSuspiciousObjCClassEnabled, !isRunning,
              application.isValidInjectionTarget else { return }
        selectedApplication = application
        persistSelectedApplication(application)
        suspiciousObjCClassStatus = "已关闭"
    }

    func setSuspiciousFilesEnabled(_ enabled: Bool) async {
        guard enabled != isSuspiciousFilesEnabled, !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        suspiciousFilesStatus = enabled ? "正在写入可疑路径…" : "正在删除本工具创建的路径…"
        let preserveRestrictedWrite = !enabled && isRestrictedWriteEnabled
        let preserveAbnormalSymlinks = isAbnormalSymlinksEnabled
        var restrictedWriteTemporarilyDisabled = false
        var abnormalSymlinksTemporarilyDisabled = false

        do {
            if preserveAbnormalSymlinks {
                let restoreResults = try await runAbnormalSymlinks(operation: "disable-symlinks")
                let restoreTargets = symlinkTargets(in: restoreResults)
                abnormalSymlinksDetails = operationDetails(from: restoreTargets, enabling: false)
                let failures = restoreTargets.filter(isOperationFailure)
                guard failures.isEmpty else {
                    abnormalSymlinksStatus = "恢复未完成：失败 \(failures.count)/7"
                    throw HelperClientError.operationRejected("先恢复异常符号链接时失败")
                }
                abnormalSymlinksTemporarilyDisabled = true
            }

            if preserveRestrictedWrite {
                let restoreResults = try await runRestrictedWrite(operation: "disable-write")
                let restoreTargets = restrictedTargets(in: restoreResults)
                restrictedWriteDetails = restrictedDetails(from: restoreTargets, enabling: false)
                let failures = restoreTargets.filter(isRestrictedFailure)
                guard failures.isEmpty else {
                    restrictedWriteStatus = "恢复未完成：失败 \(failures.count)/3"
                    throw HelperClientError.operationRejected("先恢复受限目录权限时失败")
                }
                restrictedWriteTemporarilyDisabled = true
            }

            results = try await helperClient.run(
                operation: enabled ? "apply" : "cleanup",
                rootLayout: .automatic,
                strategies: Set(EnvironmentStrategy.allCases),
                dryRun: false
            )
            isSuspiciousFilesEnabled = enabled
            defaults.set(enabled, forKey: Self.suspiciousFilesKey)
            suspiciousFilesStatus = suspiciousSummary(for: enabled, results: results)

            if preserveRestrictedWrite {
                restrictedWriteTemporarilyDisabled = false
                try await reenableRestrictedWriteEnvironment()
            }
            if preserveAbnormalSymlinks {
                abnormalSymlinksTemporarilyDisabled = false
                try await reenableAbnormalSymlinksEnvironment()
            }
        } catch {
            if restrictedWriteTemporarilyDisabled {
                try? await reenableRestrictedWriteEnvironment()
            }
            if abnormalSymlinksTemporarilyDisabled {
                try? await reenableAbnormalSymlinksEnvironment()
            }
            suspiciousFilesStatus = isSuspiciousFilesEnabled ? "已开启" : "已关闭"
            if alertMessage == nil {
                alertMessage = error.localizedDescription
            }
        }
    }

    func setRestrictedWriteEnabled(_ enabled: Bool) async {
        guard enabled != isRestrictedWriteEnabled, !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        restrictedWriteStatus = enabled ? "正在逐项设置三个目录…" : "正在恢复三个目录的原权限…"
        restrictedWriteDetails = []

        do {
            let operation = enabled
                ? "enable-write"
                : (isSuspiciousFilesEnabled ? "disable-write" : "disable-write-remove")
            let operationResults = try await runRestrictedWrite(operation: operation)
            let targetResults = restrictedTargets(in: operationResults)
            results = operationResults
            restrictedWriteDetails = restrictedDetails(from: targetResults, enabling: enabled)

            if enabled {
                let succeeded = targetResults.filter(isRestrictedEnableSuccess).count
                if succeeded == 0 {
                    let rollbackResults = try? await runRestrictedWrite(operation: "disable-write")
                    if let rollbackResults {
                        restrictedWriteDetails += restrictedDetails(
                            from: restrictedTargets(in: rollbackResults),
                            enabling: false
                        )
                    }
                    isRestrictedWriteEnabled = false
                    defaults.set(false, forKey: Self.restrictedWriteKey)
                    restrictedWriteStatus = "开启失败：成功 0/3，已尝试回滚"
                    throw HelperClientError.operationRejected("三个目录都未能设置为可写")
                }

                isRestrictedWriteEnabled = true
                defaults.set(true, forKey: Self.restrictedWriteKey)
                restrictedWriteStatus = restrictedSummary(from: operationResults, enabling: true)
                if succeeded < targetResults.count {
                    alertMessage = "只有 \(succeeded)/3 个目录设置成功，请查看逐项结果。"
                }
            } else {
                let failures = targetResults.filter(isRestrictedFailure)
                if failures.isEmpty {
                    isRestrictedWriteEnabled = false
                    defaults.set(false, forKey: Self.restrictedWriteKey)
                    restrictedWriteStatus = restrictedSummary(from: operationResults, enabling: false)
                } else {
                    isRestrictedWriteEnabled = true
                    defaults.set(true, forKey: Self.restrictedWriteKey)
                    restrictedWriteStatus = "恢复未完成：失败 \(failures.count)/3"
                    alertMessage = "有 \(failures.count) 个目录未能恢复原权限，开关保持开启，可再次尝试关闭。"
                }
            }
        } catch {
            if restrictedWriteStatus.hasPrefix("正在") {
                restrictedWriteStatus = isRestrictedWriteEnabled ? "已开启：恢复前状态" : "已关闭"
            }
            if alertMessage == nil {
                alertMessage = error.localizedDescription
            }
        }
    }

    func setAbnormalSymlinksEnabled(_ enabled: Bool) async {
        guard enabled != isAbnormalSymlinksEnabled, !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        abnormalSymlinksStatus = enabled
            ? "正在逐项构造 7 个符号链接…"
            : "正在恢复 7 个原始路径…"
        abnormalSymlinksDetails = []

        do {
            let operationResults = try await runAbnormalSymlinks(
                operation: enabled ? "enable-symlinks" : "disable-symlinks"
            )
            let targetResults = symlinkTargets(in: operationResults)
            results = operationResults
            abnormalSymlinksDetails = operationDetails(from: targetResults, enabling: enabled)

            if enabled {
                let succeeded = targetResults.filter(isOperationEnableSuccess).count
                if succeeded == 0 {
                    let rollbackResults = try? await runAbnormalSymlinks(operation: "disable-symlinks")
                    if let rollbackResults {
                        abnormalSymlinksDetails += operationDetails(
                            from: symlinkTargets(in: rollbackResults),
                            enabling: false
                        )
                    }
                    isAbnormalSymlinksEnabled = false
                    defaults.set(false, forKey: Self.abnormalSymlinksKey)
                    abnormalSymlinksStatus = "开启失败：成功 0/7，已尝试回滚"
                    throw HelperClientError.operationRejected("7 个路径都未能构造符号链接")
                }

                isAbnormalSymlinksEnabled = true
                defaults.set(true, forKey: Self.abnormalSymlinksKey)
                abnormalSymlinksStatus = "已开启：成功 \(succeeded)/7"
                if succeeded < targetResults.count {
                    alertMessage = "只有 \(succeeded)/7 个符号链接构造成功，请查看逐项结果。"
                }
            } else {
                let failures = targetResults.filter(isOperationFailure)
                if failures.isEmpty {
                    isAbnormalSymlinksEnabled = false
                    defaults.set(false, forKey: Self.abnormalSymlinksKey)
                    abnormalSymlinksStatus = "已关闭：恢复 \(targetResults.count)/7"
                } else {
                    isAbnormalSymlinksEnabled = true
                    defaults.set(true, forKey: Self.abnormalSymlinksKey)
                    abnormalSymlinksStatus = "恢复未完成：失败 \(failures.count)/7"
                    alertMessage = "有 \(failures.count) 个路径未能恢复，开关保持开启，可再次尝试关闭。"
                }
            }
        } catch {
            if abnormalSymlinksStatus.hasPrefix("正在") {
                abnormalSymlinksStatus = isAbnormalSymlinksEnabled
                    ? "已开启：恢复前状态"
                    : "已关闭"
            }
            if alertMessage == nil {
                alertMessage = error.localizedDescription
            }
        }
    }

    func setSuspiciousObjCClassEnabled(_ enabled: Bool) async {
        guard enabled != isSuspiciousObjCClassEnabled, !isRunning else { return }
        if enabled && selectedApplication?.isValidInjectionTarget != true {
            alertMessage = "请先选择检测 App。"
            suspiciousObjCClassStatus = "已关闭：请选择检测 App"
            return
        }
        isRunning = true
        defer { isRunning = false }
        suspiciousObjCClassStatus = enabled ? "正在启用运行时类…" : "正在停用运行时类…"

        do {
            let operationResults = try await helperClient.run(
                operation: enabled ? "enable-objc-class" : "disable-objc-class",
                rootLayout: .automatic,
                strategies: Set(EnvironmentStrategy.allCases),
                targetApplication: selectedApplication,
                dryRun: false
            )
            results = operationResults
            guard let result = operationResults.first else {
                throw HelperClientError.invalidOutput
            }

            if isOperationFailure(result) {
                throw HelperClientError.operationRejected(result.message)
            }

            isSuspiciousObjCClassEnabled = enabled
            defaults.set(enabled, forKey: Self.suspiciousObjCClassKey)
            let targetName = selectedApplication?.displayName ?? "目标 App"
            suspiciousObjCClassStatus = enabled
                ? "已开启：请重新打开\(targetName)"
                : "已关闭：请重新打开\(targetName)"
        } catch {
            suspiciousObjCClassStatus = isSuspiciousObjCClassEnabled
                ? "已开启：状态未改变"
                : "已关闭"
            alertMessage = error.localizedDescription
        }
    }

    private func persistSelectedApplication(_ application: InstalledApplication) {
        guard let data = try? JSONEncoder().encode(application) else { return }
        defaults.set(data, forKey: Self.selectedApplicationKey)
    }

    private func runRestrictedWrite(operation: String) async throws -> [ArtifactResult] {
        try await helperClient.run(
            operation: operation,
            rootLayout: .automatic,
            strategies: Set(EnvironmentStrategy.allCases),
            dryRun: false
        )
    }

    private func runAbnormalSymlinks(operation: String) async throws -> [ArtifactResult] {
        try await helperClient.run(
            operation: operation,
            rootLayout: .automatic,
            strategies: Set(EnvironmentStrategy.allCases),
            dryRun: false
        )
    }

    private func reenableRestrictedWriteEnvironment() async throws {
        let restrictedResults = try await runRestrictedWrite(operation: "enable-write")
        let targetResults = restrictedTargets(in: restrictedResults)
        let succeeded = targetResults.filter(isRestrictedEnableSuccess).count
        restrictedWriteDetails = restrictedDetails(from: targetResults, enabling: true)
        guard succeeded > 0 else {
            _ = try? await runRestrictedWrite(operation: "disable-write")
            isRestrictedWriteEnabled = false
            defaults.set(false, forKey: Self.restrictedWriteKey)
            restrictedWriteStatus = "已关闭：可写环境未能保留"
            throw HelperClientError.operationRejected("三个目录都未能设置为可写")
        }

        isRestrictedWriteEnabled = true
        defaults.set(true, forKey: Self.restrictedWriteKey)
        restrictedWriteStatus = restrictedSummary(from: restrictedResults, enabling: true)
        if succeeded < 3 {
            alertMessage = "只有 \(succeeded)/3 个目录设置成功，请查看逐项结果。"
        }
    }

    private func reenableAbnormalSymlinksEnvironment() async throws {
        let operationResults = try await runAbnormalSymlinks(operation: "enable-symlinks")
        let targetResults = symlinkTargets(in: operationResults)
        let succeeded = targetResults.filter(isOperationEnableSuccess).count
        abnormalSymlinksDetails = operationDetails(from: targetResults, enabling: true)
        guard succeeded > 0 else {
            _ = try? await runAbnormalSymlinks(operation: "disable-symlinks")
            isAbnormalSymlinksEnabled = false
            defaults.set(false, forKey: Self.abnormalSymlinksKey)
            abnormalSymlinksStatus = "已关闭：符号链接环境未能保留"
            throw HelperClientError.operationRejected("7 个路径都未能构造符号链接")
        }

        isAbnormalSymlinksEnabled = true
        defaults.set(true, forKey: Self.abnormalSymlinksKey)
        abnormalSymlinksStatus = "已开启：成功 \(succeeded)/7"
        if succeeded < 7 {
            alertMessage = "只有 \(succeeded)/7 个符号链接构造成功，请查看逐项结果。"
        }
    }

    private func restrictedTargets(in results: [ArtifactResult]) -> [ArtifactResult] {
        let paths: Set<String> = ["/root", "/private", "/jb"]
        return results.filter { paths.contains($0.path) }
    }

    private func isRestrictedEnableSuccess(_ result: ArtifactResult) -> Bool {
        isOperationEnableSuccess(result)
    }

    private func isRestrictedFailure(_ result: ArtifactResult) -> Bool {
        isOperationFailure(result)
    }

    private func restrictedSummary(from results: [ArtifactResult], enabling: Bool) -> String {
        let targets = restrictedTargets(in: results)
        let rootMessage = results.first(where: { $0.path == "/" })?.message ?? ""
        let rootStatus = rootMessage.contains("read-only")
            ? "根文件系统只读"
            : (rootMessage.contains("writable") ? "根文件系统可写" : "根文件系统状态未知")
        if enabling {
            let succeeded = targets.filter(isRestrictedEnableSuccess).count
            return "已开启：成功 \(succeeded)/3；\(rootStatus)"
        }
        let restored = targets.filter { !isRestrictedFailure($0) }.count
        return "已关闭：恢复 \(restored)/3"
    }

    private func restrictedDetails(
        from results: [ArtifactResult],
        enabling: Bool
    ) -> [String] {
        operationDetails(from: results, enabling: enabling)
    }

    private func symlinkTargets(in results: [ArtifactResult]) -> [ArtifactResult] {
        let paths: Set<String> = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/include",
            "/usr/libexec",
            "/usr/share",
            "/var/lib/undecimus/apt"
        ]
        return results.filter { paths.contains($0.path) }
    }

    private func isOperationEnableSuccess(_ result: ArtifactResult) -> Bool {
        result.status == .created || result.status == .alreadyPresent
    }

    private func isOperationFailure(_ result: ArtifactResult) -> Bool {
        result.status == .failed || result.status == .protected
    }

    private func operationDetails(
        from results: [ArtifactResult],
        enabling: Bool
    ) -> [String] {
        results.map { result in
            let succeeded = enabling
                ? isOperationEnableSuccess(result)
                : !isOperationFailure(result)
            let symbol = succeeded ? "✓" : "✕"
            let mapped = result.path == result.effectivePath
                ? result.path
                : "\(result.path) → \(result.effectivePath)"
            return succeeded
                ? "\(symbol) \(mapped)"
                : "\(symbol) \(mapped)：\(result.message)"
        }
    }

    private func suspiciousSummary(for enabled: Bool, results: [ArtifactResult]) -> String {
        let failed = results.filter { $0.status == .failed }.count
        if enabled {
            let created = results.filter { $0.status == .created }.count
            let existing = results.filter { $0.status == .protected }.count
            return failed == 0
                ? "已开启：写入 \(created) 项，原已存在 \(existing) 项"
                : "已开启：写入 \(created) 项，失败 \(failed) 项"
        }

        let removed = results.filter { $0.status == .removed }.count
        return failed == 0
            ? "已关闭：删除本工具创建的 \(removed) 项"
            : "已关闭：删除 \(removed) 项，失败 \(failed) 项"
    }
}
