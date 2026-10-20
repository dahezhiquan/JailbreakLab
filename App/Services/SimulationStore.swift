import Foundation
import Combine

@MainActor
final class SimulationStore: ObservableObject {
    @Published var selectedStrategies: Set<EnvironmentStrategy> = [.jailbreakMarkers]
    @Published var operationMode: OperationMode = .dryRun
    @Published var rootLayout: RootLayout = .automatic
    @Published var riskAcknowledged = false
    @Published private(set) var results: [ArtifactResult] = []
    @Published private(set) var isRunning = false
    @Published var alertMessage: String?

    private let helperClient = HelperClient()

    var selectedArtifacts: [DetectionArtifact] {
        ArtifactCatalog.all.filter { selectedStrategies.contains($0.strategy) }
    }

    var canApply: Bool {
        !selectedStrategies.isEmpty
            && !isRunning
            && (operationMode == .dryRun || riskAcknowledged)
    }

    func setStrategy(_ strategy: EnvironmentStrategy, enabled: Bool) {
        if enabled {
            selectedStrategies.insert(strategy)
        } else {
            selectedStrategies.remove(strategy)
        }
    }

    func probe() async {
        await execute(operation: "probe", dryRun: true)
    }

    func apply() async {
        await execute(operation: "apply", dryRun: operationMode == .dryRun)
    }

    func clean() async {
        await execute(operation: "cleanup", dryRun: operationMode == .dryRun)
    }

    private func execute(operation: String, dryRun: Bool) async {
        guard !selectedStrategies.isEmpty else { return }
        isRunning = true
        defer { isRunning = false }

        do {
            results = try await helperClient.run(
                operation: operation,
                rootLayout: rootLayout,
                strategies: selectedStrategies,
                dryRun: dryRun
            )
        } catch {
            alertMessage = error.localizedDescription
        }
    }
}
