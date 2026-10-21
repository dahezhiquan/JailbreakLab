import XCTest
@testable import JailbreakLab

@MainActor
final class SimulationStoreTests: XCTestCase {
    func testStoreStartsIdleWithAStatusMessage() {
        let store = SimulationStore()
        XCTAssertFalse(store.isRunning)
        XCTAssertFalse(store.suspiciousFilesStatus.isEmpty)
        XCTAssertFalse(store.restrictedWriteStatus.isEmpty)
        XCTAssertFalse(store.suspiciousObjCClassStatus.isEmpty)
    }

    func testSingleSwitchCoversEveryArtifactGroup() {
        let coveredStrategies = Set(ArtifactCatalog.all.map(\.strategy))
        XCTAssertEqual(coveredStrategies, Set(EnvironmentStrategy.allCases))
    }
}
