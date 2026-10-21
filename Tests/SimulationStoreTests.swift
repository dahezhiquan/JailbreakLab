import XCTest
@testable import JailbreakLab

@MainActor
final class SimulationStoreTests: XCTestCase {
    func testStoreStartsIdleWithAStatusMessage() {
        let store = SimulationStore()
        XCTAssertFalse(store.isRunning)
        XCTAssertFalse(store.suspiciousFilesStatus.isEmpty)
        XCTAssertFalse(store.restrictedWriteStatus.isEmpty)
        XCTAssertFalse(store.debuggerStateStatus.isEmpty)
        XCTAssertFalse(store.suspiciousObjCClassStatus.isEmpty)
        XCTAssertFalse(store.runtimeHookStatus.isEmpty)
        XCTAssertFalse(store.mshookStatus.isEmpty)
    }

    func testSingleSwitchCoversEveryArtifactGroup() {
        let coveredStrategies = Set(ArtifactCatalog.all.map(\.strategy))
        XCTAssertEqual(coveredStrategies, Set(EnvironmentStrategy.allCases))
    }

    func testInjectionTargetValidationRejectsTraversalAndMarkup() {
        let traversal = InstalledApplication(
            bundleIdentifier: "com.example.detector",
            displayName: "Detector",
            bundleName: "../Detector.app",
            executableName: "Detector"
        )
        let markup = InstalledApplication(
            bundleIdentifier: "com.example.<detector>",
            displayName: "Detector",
            bundleName: "Detector.app",
            executableName: "Detector"
        )
        XCTAssertFalse(traversal.isValidInjectionTarget)
        XCTAssertFalse(markup.isValidInjectionTarget)
        let valid = InstalledApplication(
            bundleIdentifier: "com.example.detector",
            displayName: "Detector",
            bundleName: "Detector.app",
            executableName: "Detector"
        )
        XCTAssertTrue(valid.isValidInjectionTarget)
    }

    func testLegacyEnabledStateWithoutTargetIsResetForSelection() {
        let suiteName = "SimulationStoreTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(true, forKey: "SuspiciousObjCClassEnvironmentEnabled")

        let store = SimulationStore(defaults: defaults, applicationLoader: { [] })

        XCTAssertNil(store.selectedApplication)
        XCTAssertFalse(store.isSuspiciousObjCClassEnabled)
        XCTAssertEqual(store.suspiciousObjCClassStatus, "已关闭：请选择检测 App")
    }

    func testApplicationSelectionIsStoredWhileStrategyIsDisabled() {
        let suiteName = "SimulationStoreTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let target = InstalledApplication(
            bundleIdentifier: "com.example.detector",
            displayName: "Detector",
            bundleName: "Detector.app",
            executableName: "Detector"
        )
        let store = SimulationStore(defaults: defaults, applicationLoader: { [target] })

        store.selectApplication(target)

        XCTAssertEqual(store.selectedApplication, target)
        XCTAssertEqual(store.debuggerStateStatus, "已关闭")
        XCTAssertEqual(store.suspiciousObjCClassStatus, "已关闭")
        XCTAssertEqual(store.runtimeHookStatus, "已关闭")
        XCTAssertEqual(store.mshookStatus, "已关闭")
    }

    func testLegacyDebuggerStateWithoutTargetIsResetForSelection() {
        let suiteName = "SimulationStoreTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(true, forKey: "DebuggerStateEnvironmentEnabled")

        let store = SimulationStore(defaults: defaults, applicationLoader: { [] })

        XCTAssertNil(store.selectedApplication)
        XCTAssertFalse(store.isDebuggerStateEnabled)
        XCTAssertEqual(store.debuggerStateStatus, "已关闭：请选择检测 App")
    }

    func testLegacyRuntimeHookStateWithoutTargetIsResetForSelection() {
        let suiteName = "SimulationStoreTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(true, forKey: "RuntimeHookEnvironmentEnabled")

        let store = SimulationStore(defaults: defaults, applicationLoader: { [] })

        XCTAssertNil(store.selectedApplication)
        XCTAssertFalse(store.isRuntimeHookEnabled)
        XCTAssertEqual(store.runtimeHookStatus, "已关闭：请选择检测 App")
    }

    func testLegacyMSHookStateWithoutTargetIsResetForSelection() {
        let suiteName = "SimulationStoreTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defer { defaults.removePersistentDomain(forName: suiteName) }
        defaults.set(true, forKey: "MSHookEnvironmentEnabled")

        let store = SimulationStore(defaults: defaults, applicationLoader: { [] })

        XCTAssertNil(store.selectedApplication)
        XCTAssertFalse(store.isMSHookEnabled)
        XCTAssertEqual(store.mshookStatus, "已关闭：请选择检测 App")
    }
}
