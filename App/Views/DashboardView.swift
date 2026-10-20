import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var store: SimulationStore
    @State private var showingArtifacts = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    summaryCard
                    configurationCard
                    strategyCard
                    actionCard
                    if !store.results.isEmpty {
                        ResultListView(results: store.results)
                    }
                }
                .padding(16)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("Jailbreak Lab")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showingArtifacts = true } label: {
                        Label("路径目录", systemImage: "list.bullet.rectangle")
                    }
                    .accessibilityLabel("查看路径目录")
                }
            }
            .sheet(isPresented: $showingArtifacts) {
                ArtifactCatalogView(artifacts: store.selectedArtifacts)
            }
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
        .tint(Color(red: 0.05, green: 0.64, blue: 0.45))
    }

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 26, weight: .semibold))
                    .foregroundStyle(.mint)
                    .frame(width: 44, height: 44)
                    .background(.mint.opacity(0.14), in: RoundedRectangle(cornerRadius: 12))
                VStack(alignment: .leading, spacing: 4) {
                    Text("越狱特征环境模拟")
                        .font(.headline)
                    Text("用于验证 App 的多层文件检测策略，仅应运行于你控制的越狱测试设备。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            HStack(spacing: 8) {
                statusPill("\(store.selectedStrategies.count) 组策略", symbol: "switch.2")
                statusPill("\(store.selectedArtifacts.count) 个路径", symbol: "point.3.connected.trianglepath.dotted")
            }
        }
        .labCard()
    }

    private var configurationCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("运行配置", systemImage: "slider.horizontal.3")
                .font(.headline)

            VStack(alignment: .leading, spacing: 7) {
                Text("操作模式")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Picker("操作模式", selection: $store.operationMode) {
                    ForEach(OperationMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
            }

            VStack(alignment: .leading, spacing: 7) {
                Text("越狱根布局")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Picker("越狱根布局", selection: $store.rootLayout) {
                    ForEach(RootLayout.allCases) { layout in
                        Text(layout.title).tag(layout)
                    }
                }
                .pickerStyle(.segmented)
            }

            if store.operationMode == .live {
                Toggle(isOn: $store.riskAcknowledged) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("我确认这是隔离测试设备")
                            .font(.subheadline.weight(.semibold))
                        Text("不会覆盖现有对象，但会在系统目录创建可见特征。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .accessibilityLabel("确认隔离测试设备")
            }
        }
        .labCard()
    }

    private var strategyCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label("环境策略", systemImage: "square.stack.3d.up")
                .font(.headline)
                .padding(.bottom, 8)

            ForEach(EnvironmentStrategy.allCases) { strategy in
                Toggle(
                    isOn: Binding(
                        get: { store.selectedStrategies.contains(strategy) },
                        set: { store.setStrategy(strategy, enabled: $0) }
                    )
                ) {
                    HStack(spacing: 12) {
                        Image(systemName: strategy.symbol)
                            .font(.system(size: 17, weight: .semibold))
                            .foregroundStyle(.cyan)
                            .frame(width: 34, height: 34)
                            .background(.cyan.opacity(0.12), in: RoundedRectangle(cornerRadius: 9))
                        VStack(alignment: .leading, spacing: 2) {
                            Text(strategy.title)
                                .font(.subheadline.weight(.semibold))
                            Text(strategy.subtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 7)
                }
                .accessibilityLabel(strategy.title)

                if strategy != EnvironmentStrategy.allCases.last {
                    Divider().padding(.leading, 46)
                }
            }
        }
        .labCard()
    }

    private var actionCard: some View {
        VStack(spacing: 12) {
            Button {
                Task { await store.apply() }
            } label: {
                HStack {
                    if store.isRunning {
                        ProgressView().tint(.black)
                    } else {
                        Image(systemName: store.operationMode == .dryRun ? "play.circle.fill" : "bolt.shield.fill")
                    }
                    Text(store.operationMode == .dryRun ? "预演创建计划" : "应用环境策略")
                        .fontWeight(.semibold)
                    Spacer()
                    Image(systemName: "chevron.right")
                }
                .padding(.horizontal, 16)
                .frame(minHeight: 52)
            }
            .buttonStyle(.plain)
            .foregroundStyle(.black)
            .background(.mint, in: RoundedRectangle(cornerRadius: 14))
            .disabled(!store.canApply)
            .opacity(store.canApply ? 1 : 0.45)
            .accessibilityLabel(store.operationMode == .dryRun ? "预演创建计划" : "应用环境策略")

            HStack(spacing: 10) {
                secondaryButton("检查当前环境", symbol: "magnifyingglass") {
                    Task { await store.probe() }
                }
                secondaryButton("清理工具痕迹", symbol: "trash") {
                    Task { await store.clean() }
                }
            }

            Label("清理只会删除内容签名匹配且由本工具创建的对象。", systemImage: "lock.shield")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .labCard()
    }

    private func secondaryButton(
        _ title: String,
        symbol: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Label(title, systemImage: symbol)
                .font(.caption.weight(.semibold))
                .lineLimit(1)
                .frame(maxWidth: .infinity)
                .frame(minHeight: 42)
        }
        .buttonStyle(.plain)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .stroke(.white.opacity(0.09), lineWidth: 1)
        }
        .disabled(store.isRunning || store.selectedStrategies.isEmpty)
        .accessibilityLabel(title)
    }

    private func statusPill(_ title: String, symbol: String) -> some View {
        Label(title, systemImage: symbol)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(.white.opacity(0.07), in: Capsule())
    }
}

extension View {
    func labCard() -> some View {
        self
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(.white.opacity(0.07), lineWidth: 1)
            }
    }
}
