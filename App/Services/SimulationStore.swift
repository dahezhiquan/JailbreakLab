import Foundation
import Combine

@MainActor
final class SimulationStore: ObservableObject {
    @Published private(set) var isSuspiciousFilesEnabled: Bool
    @Published private(set) var suspiciousFilesStatus: String
    @Published private(set) var isRestrictedWriteEnabled: Bool
    @Published private(set) var restrictedWriteStatus: String
    @Published private(set) var results: [ArtifactResult] = []
    @Published private(set) var isRunning = false
    @Published var alertMessage: String?

    private let helperClient = HelperClient()
    private let defaults = UserDefaults.standard
    private static let suspiciousFilesKey = "SuspiciousFilesEnvironmentEnabled"
    private static let restrictedWriteKey = "RestrictedWriteEnvironmentEnabled"

    init() {
        let suspiciousFilesEnabled = UserDefaults.standard.bool(forKey: Self.suspiciousFilesKey)
        let restrictedWriteEnabled = UserDefaults.standard.bool(forKey: Self.restrictedWriteKey)
        isSuspiciousFilesEnabled = suspiciousFilesEnabled
        suspiciousFilesStatus = suspiciousFilesEnabled ? "已开启" : "已关闭"
        isRestrictedWriteEnabled = restrictedWriteEnabled
        restrictedWriteStatus = restrictedWriteEnabled ? "已开启：/jb/ 可写" : "已关闭"
    }

    func setSuspiciousFilesEnabled(_ enabled: Bool) async {
        guard enabled != isSuspiciousFilesEnabled, !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        suspiciousFilesStatus = enabled ? "正在写入可疑路径…" : "正在删除本工具创建的路径…"

        do {
            results = try await helperClient.run(
                operation: enabled ? "apply" : "cleanup",
                rootLayout: .automatic,
                strategies: Set(EnvironmentStrategy.allCases),
                dryRun: false
            )
            isSuspiciousFilesEnabled = enabled
            defaults.set(enabled, forKey: Self.suspiciousFilesKey)
            suspiciousFilesStatus = suspiciousSummary(for: enabled, results: results)

            if !enabled && isRestrictedWriteEnabled {
                do {
                    let restrictedResults = try await runRestrictedWrite(operation: "enable-write")
                    if let rejected = restrictedResults.first(where: {
                        $0.status == .failed || $0.status == .protected
                    }) {
                        throw HelperClientError.operationRejected(rejected.message)
                    }
                } catch {
                    isRestrictedWriteEnabled = false
                    defaults.set(false, forKey: Self.restrictedWriteKey)
                    restrictedWriteStatus = "已关闭：/jb/ 可写环境未能保留"
                    alertMessage = error.localizedDescription
                }
            }
        } catch {
            suspiciousFilesStatus = isSuspiciousFilesEnabled ? "已开启" : "已关闭"
            alertMessage = error.localizedDescription
        }
    }

    func setRestrictedWriteEnabled(_ enabled: Bool) async {
        guard enabled != isRestrictedWriteEnabled, !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        restrictedWriteStatus = enabled ? "正在设置 /jb/ 可写…" : "正在恢复 /jb/ 权限…"

        do {
            let operation = enabled
                ? "enable-write"
                : (isSuspiciousFilesEnabled ? "disable-write" : "disable-write-remove")
            let operationResults = try await runRestrictedWrite(operation: operation)
            if let rejected = operationResults.first(where: {
                $0.status == .failed || $0.status == .protected
            }) {
                throw HelperClientError.operationRejected(rejected.message)
            }
            results = operationResults
            isRestrictedWriteEnabled = enabled
            defaults.set(enabled, forKey: Self.restrictedWriteKey)
            let rootMessage = operationResults.first(where: { $0.path == "/" })?.message ?? ""
            let rootStatus = rootMessage.contains("read-only")
                ? "根文件系统只读"
                : (rootMessage.contains("writable") ? "根文件系统可写" : "根文件系统状态未知")
            let writablePath = operationResults.first(where: { $0.path == "/jb" })?.effectivePath ?? "/jb"
            restrictedWriteStatus = enabled
                ? "已开启：\(rootStatus)；\(writablePath) 写入测试成功"
                : "已关闭：/jb/ 已恢复"
        } catch {
            restrictedWriteStatus = isRestrictedWriteEnabled ? "已开启：/jb/ 可写" : "已关闭"
            alertMessage = error.localizedDescription
        }
    }

    private func runRestrictedWrite(operation: String) async throws -> [ArtifactResult] {
        try await helperClient.run(
            operation: operation,
            rootLayout: .automatic,
            strategies: Set(EnvironmentStrategy.allCases),
            dryRun: false
        )
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
