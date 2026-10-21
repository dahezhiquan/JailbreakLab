import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var store: SimulationStore

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    strategyRows(
                        title: "可疑文件是否存在",
                        detail: "写入越狱特征路径",
                        isOn: store.isSuspiciousFilesEnabled,
                        status: store.suspiciousFilesStatus,
                        symbol: "doc.badge.plus"
                    ) { enabled in
                        await store.setSuspiciousFilesEnabled(enabled)
                    }
                }

                Section {
                    strategyRows(
                        title: "受限目录是否可写",
                        detail: "尝试使 /root/、/private/、/jb/ 可写",
                        isOn: store.isRestrictedWriteEnabled,
                        status: store.restrictedWriteStatus,
                        details: store.restrictedWriteDetails,
                        symbol: "folder.badge.gearshape"
                    ) { enabled in
                        await store.setRestrictedWriteEnabled(enabled)
                    }
                }

                Section {
                    strategyRows(
                        title: "异常符号链接",
                        detail: "构造 7 个关键目录符号链接",
                        isOn: store.isAbnormalSymlinksEnabled,
                        status: store.abnormalSymlinksStatus,
                        details: store.abnormalSymlinksDetails,
                        symbol: "link.badge.plus"
                    ) { enabled in
                        await store.setAbnormalSymlinksEnabled(enabled)
                    }
                }

                Section {
                    NavigationLink {
                        ApplicationSelectionView()
                    } label: {
                        Label {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(store.selectedApplication?.displayName ?? "选择检测 App")
                                    .font(.headline)
                                Text(store.selectedApplication?.bundleIdentifier ?? "尚未选择")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        } icon: {
                            Image(systemName: "app.badge.checkmark")
                                .foregroundStyle(.green)
                        }
                    }
                    .disabled(
                        store.isRunning || store.isSuspiciousObjCClassEnabled ||
                            store.isRuntimeHookEnabled || store.isMSHookEnabled
                    )

                    strategyRows(
                        title: "可疑 Objective-C 类是否存在",
                        detail: store.selectedApplication.map {
                            "为\($0.displayName)注册 ShadowRuleset"
                        } ?? "选择目标后注册 ShadowRuleset",
                        isOn: store.isSuspiciousObjCClassEnabled,
                        status: store.suspiciousObjCClassStatus,
                        symbol: "curlybraces.square",
                        isDisabled: store.selectedApplication == nil
                    ) { enabled in
                        await store.setSuspiciousObjCClassEnabled(enabled)
                    }

                    strategyRows(
                        title: "Runtime Hook 检测",
                        detail: store.selectedApplication.map {
                            "替换 \($0.displayName) 中 -[NSProcessInfo processName] 的 IMP"
                        } ?? "选择目标后替换 -[NSProcessInfo processName] 的 IMP",
                        isOn: store.isRuntimeHookEnabled,
                        status: store.runtimeHookStatus,
                        symbol: "point.3.connected.trianglepath.dotted",
                        isDisabled: store.selectedApplication == nil
                    ) { enabled in
                        await store.setRuntimeHookEnabled(enabled)
                    }

                    strategyRows(
                        title: "MSHookFunction 检测",
                        detail: store.selectedApplication.map {
                            "在\($0.displayName) 中 inline hook getpid"
                        } ?? "选择目标后 inline hook getpid",
                        isOn: store.isMSHookEnabled,
                        status: store.mshookStatus,
                        symbol: "arrow.triangle.branch",
                        isDisabled: store.selectedApplication == nil
                    ) { enabled in
                        await store.setMSHookEnabled(enabled)
                    }
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
            .task {
                await store.refreshInstalledApplications()
            }
        }
        .tint(.green)
    }

    @ViewBuilder
    private func strategyRows(
        title: String,
        detail: String,
        isOn: Bool,
        status: String,
        details: [String] = [],
        symbol: String,
        isDisabled: Bool = false,
        action: @escaping @MainActor (Bool) async -> Void
    ) -> some View {
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
        .disabled(store.isRunning || isDisabled)
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

        ForEach(details, id: \.self) { detail in
            Text(detail)
                .font(.caption.monospaced())
                .foregroundStyle(detail.hasPrefix("✓") ? Color.secondary : Color.red)
                .textSelection(.enabled)
        }
    }
}

private struct ApplicationSelectionView: View {
    @EnvironmentObject private var store: SimulationStore
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""

    private var filteredApplications: [InstalledApplication] {
        let normalized = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return store.installedApplications }
        return store.installedApplications.filter {
            $0.displayName.localizedCaseInsensitiveContains(normalized) ||
                $0.bundleIdentifier.localizedCaseInsensitiveContains(normalized)
        }
    }

    var body: some View {
        Group {
            if store.installedApplications.isEmpty && store.isLoadingApplications {
                ProgressView("正在读取 App…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if store.installedApplications.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "app.dashed")
                        .font(.title)
                        .foregroundStyle(.secondary)
                    Text("未找到可选 App")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(filteredApplications) { application in
                    Button {
                        store.selectApplication(application)
                        dismiss()
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "app.fill")
                                .foregroundStyle(.green)
                                .frame(width: 24, height: 24)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(application.displayName)
                                    .foregroundStyle(.primary)
                                Text(application.bundleIdentifier)
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                            Spacer(minLength: 8)
                            if application.id == store.selectedApplication?.id {
                                Image(systemName: "checkmark")
                                    .font(.headline)
                                    .foregroundStyle(.green)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .navigationTitle("选择检测 App")
        .searchable(text: $query, prompt: "名称或 Bundle ID")
        .toolbar {
            ToolbarItem {
                Button {
                    Task { await store.refreshInstalledApplications() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(store.isLoadingApplications)
                .accessibilityLabel("刷新 App 列表")
            }
        }
        .task {
            if store.installedApplications.isEmpty {
                await store.refreshInstalledApplications()
            }
        }
    }
}
