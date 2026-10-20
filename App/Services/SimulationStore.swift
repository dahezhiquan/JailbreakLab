import Foundation
import Combine

@MainActor
final class SimulationStore: ObservableObject {
    @Published private(set) var isEnabled: Bool
    @Published private(set) var statusMessage: String
    @Published private(set) var results: [ArtifactResult] = []
    @Published private(set) var isRunning = false
    @Published var alertMessage: String?

    private let helperClient = HelperClient()
    private let defaults = UserDefaults.standard
    private static let enabledKey = "SuspiciousFilesEnvironmentEnabled"

    init() {
        let enabled = UserDefaults.standard.bool(forKey: Self.enabledKey)
        isEnabled = enabled
        statusMessage = enabled ? "已开启" : "已关闭"
    }

    func setEnabled(_ enabled: Bool) async {
        guard enabled != isEnabled, !isRunning else { return }
        isRunning = true
        defer { isRunning = false }
        statusMessage = enabled ? "正在写入可疑路径…" : "正在删除本工具创建的路径…"

        do {
            results = try await helperClient.run(
                operation: enabled ? "apply" : "cleanup",
                rootLayout: .automatic,
                strategies: Set(EnvironmentStrategy.allCases),
                dryRun: false
            )
            isEnabled = enabled
            defaults.set(enabled, forKey: Self.enabledKey)
            statusMessage = summary(for: enabled, results: results)
        } catch {
            statusMessage = isEnabled ? "已开启" : "已关闭"
            alertMessage = error.localizedDescription
        }
    }

    private func summary(for enabled: Bool, results: [ArtifactResult]) -> String {
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
