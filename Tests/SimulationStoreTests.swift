import XCTest
@testable import JailbreakLab

@MainActor
final class SimulationStoreTests: XCTestCase {
    func testLiveApplyRequiresAcknowledgement() {
        let store = SimulationStore()
        store.operationMode = .live
        store.riskAcknowledged = false
        XCTAssertFalse(store.canApply)
        store.riskAcknowledged = true
        XCTAssertTrue(store.canApply)
    }

    func testDisablingAllStrategiesDisablesApply() {
        let store = SimulationStore()
        for strategy in EnvironmentStrategy.allCases {
            store.setStrategy(strategy, enabled: false)
        }
        XCTAssertFalse(store.canApply)
        XCTAssertTrue(store.selectedArtifacts.isEmpty)
    }
}
