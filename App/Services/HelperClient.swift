import Foundation
import Darwin

enum HelperClientError: LocalizedError {
    case unavailable
    case executionFailed(Int32)
    case invalidOutput
    case operationRejected(String)

    var errorDescription: String? {
        switch self {
        case .unavailable:
            "未找到特权 helper。请使用越狱安装包安装后重试。"
        case .executionFailed(let code):
            "helper 执行失败（错误码 \(code)）。"
        case .invalidOutput:
            "helper 返回了无法解析的结果。"
        case .operationRejected(let message):
            "操作被拒绝：\(message)"
        }
    }
}

struct HelperClient: Sendable {
    func run(
        operation: String,
        rootLayout: RootLayout,
        strategies: Set<EnvironmentStrategy>,
        targetApplication: InstalledApplication? = nil,
        dryRun: Bool
    ) async throws -> [ArtifactResult] {
        try await Task.detached(priority: .userInitiated) {
            let groups = strategies
                .map(\.rawValue)
                .sorted()
                .joined(separator: ",")
            let bundleIdentifier = targetApplication?.bundleIdentifier ?? ""
            let bundleName = targetApplication?.bundleName ?? ""
            let executableName = targetApplication?.executableName ?? ""

            var exitCode: Int32 = 0
            let pointer = operation.withCString { operationPointer in
                rootLayout.rawValue.withCString { rootPointer in
                    groups.withCString { groupsPointer in
                        bundleIdentifier.withCString { bundleIdentifierPointer in
                            bundleName.withCString { bundleNamePointer in
                                executableName.withCString { executableNamePointer in
                                    JBRunHelper(
                                        operationPointer,
                                        rootPointer,
                                        groupsPointer,
                                        bundleIdentifierPointer,
                                        bundleNamePointer,
                                        executableNamePointer,
                                        dryRun,
                                        &exitCode
                                    )
                                }
                            }
                        }
                    }
                }
            }

            guard let pointer else {
                throw HelperClientError.executionFailed(exitCode)
            }
            defer { JBFreeHelperOutput(pointer) }

            let output = String(cString: pointer)
            if exitCode == ENOENT {
                throw HelperClientError.unavailable
            }
            guard exitCode == 0 else {
                throw HelperClientError.executionFailed(exitCode)
            }

            let decoder = JSONDecoder()
            let lines = output.split(separator: "\n", omittingEmptySubsequences: true)
            let results = lines.compactMap { line in
                try? decoder.decode(ArtifactResult.self, from: Data(line.utf8))
            }
            guard results.count == lines.count else {
                throw HelperClientError.invalidOutput
            }
            return results
        }.value
    }
}
