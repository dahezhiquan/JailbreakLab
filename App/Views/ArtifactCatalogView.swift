import SwiftUI

struct ArtifactCatalogView: View {
    @Environment(\.dismiss) private var dismiss
    let artifacts: [DetectionArtifact]

    var body: some View {
        NavigationStack {
            List {
                ForEach(EnvironmentStrategy.allCases) { strategy in
                    let matching = artifacts.filter { $0.strategy == strategy }
                    if !matching.isEmpty {
                        Section(strategy.title) {
                            ForEach(matching) { artifact in
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(artifact.path)
                                        .font(.system(.caption, design: .monospaced))
                                        .textSelection(.enabled)
                                    Text(artifact.kind.label)
                                        .font(.caption2.weight(.medium))
                                        .foregroundStyle(artifact.kind == .probeOnly ? .orange : .mint)
                                }
                                .padding(.vertical, 3)
                            }
                        }
                    }
                }
            }
            .navigationTitle("路径目录")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { dismiss() }
                }
            }
        }
        .preferredColorScheme(.dark)
    }
}
