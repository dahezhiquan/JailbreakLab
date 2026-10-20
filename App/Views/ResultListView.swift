import SwiftUI

struct ResultListView: View {
    let results: [ArtifactResult]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("执行结果", systemImage: "doc.text.magnifyingglass")
                    .font(.headline)
                Spacer()
                Text(summary)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            LazyVStack(spacing: 0) {
                ForEach(results) { result in
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: symbol(for: result.status))
                            .foregroundStyle(color(for: result.status))
                            .frame(width: 20)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(result.path)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                            if result.effectivePath != result.path {
                                Text("实际：\(result.effectivePath)")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.cyan)
                                    .textSelection(.enabled)
                            }
                            Text("\(result.status.title) · \(result.message)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 10)
                    if result.id != results.last?.id {
                        Divider().padding(.leading, 30)
                    }
                }
            }
        }
        .labCard()
    }

    private var summary: String {
        let successful = results.filter { [.created, .removed, .planned, .alreadyPresent].contains($0.status) }.count
        return "\(successful)/\(results.count)"
    }

    private func symbol(for status: ArtifactStatus) -> String {
        switch status {
        case .created, .removed, .alreadyPresent: "checkmark.circle.fill"
        case .planned: "clock.fill"
        case .absent: "minus.circle"
        case .probeOnly: "eye.fill"
        case .protected: "lock.fill"
        case .failed: "xmark.octagon.fill"
        }
    }

    private func color(for status: ArtifactStatus) -> Color {
        switch status {
        case .created, .removed, .alreadyPresent: .mint
        case .planned: .cyan
        case .absent: .secondary
        case .probeOnly, .protected: .orange
        case .failed: .red
        }
    }
}
