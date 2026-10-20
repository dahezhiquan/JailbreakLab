import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var store: SimulationStore

    var body: some View {
        NavigationStack {
            Form {
                strategyRow(
                    title: "可疑文件是否存在",
                    detail: "写入越狱特征路径",
                    isOn: store.isSuspiciousFilesEnabled,
                    status: store.suspiciousFilesStatus,
                    symbol: "doc.badge.plus"
                ) { enabled in
                    await store.setSuspiciousFilesEnabled(enabled)
                }

                strategyRow(
                    title: "受限目录是否可写",
                    detail: "使 /jb/ 具有可写权限（rootless 自动映射）",
                    isOn: store.isRestrictedWriteEnabled,
                    status: store.restrictedWriteStatus,
                    symbol: "folder.badge.gearshape"
                ) { enabled in
                    await store.setRestrictedWriteEnabled(enabled)
                }
            }
            .navigationTitle("Jailbreak Lab")
            .alert(
                "操作未完成",
                isPresented: Binding(
                    get: { store.alertMessage != nil },
                    set: { if !$0 { store.alertMessage = nil } }
                )
            ) {
                Button("知道了", role: .cancel) { store.alertMessage = nil }
            } message: {
                Text(store.alertMessage ?? "")
            }
        }
        .tint(.green)
    }

    private func strategyRow(
        title: String,
        detail: String,
        isOn: Bool,
        status: String,
        symbol: String,
        action: @escaping @MainActor (Bool) async -> Void
    ) -> some View {
        Section {
            Toggle(
                isOn: Binding(
                    get: { isOn },
                    set: { enabled in Task { @MainActor in await action(enabled) } }
                )
            ) {
                Label {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(title)
                            .font(.headline)
                        Text(detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: symbol)
                        .foregroundStyle(.green)
                }
            }
            .disabled(store.isRunning)
            .accessibilityLabel(title)

            HStack(spacing: 10) {
                if store.isRunning {
                    ProgressView()
                } else {
                    Image(systemName: isOn ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(isOn ? .green : .secondary)
                }
                Text(status)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
