import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var store: SimulationStore

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle(
                        isOn: Binding(
                            get: { store.isEnabled },
                            set: { enabled in
                                Task { await store.setEnabled(enabled) }
                            }
                        )
                    ) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("可疑文件是否存在")
                                .font(.headline)
                            Text("开启时写入越狱特征，关闭时仅删除本工具创建的内容")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .disabled(store.isRunning)
                    .accessibilityLabel("可疑文件是否存在")

                    HStack(spacing: 10) {
                        if store.isRunning {
                            ProgressView()
                        } else {
                            Image(systemName: store.isEnabled ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(store.isEnabled ? .green : .secondary)
                        }
                        Text(store.statusMessage)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("环境策略")
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
}
