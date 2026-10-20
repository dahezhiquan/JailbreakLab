import XCTest
@testable import JailbreakLab

final class ArtifactCatalogTests: XCTestCase {
    func testPathsAreUniqueAndAbsolute() {
        let paths = ArtifactCatalog.all.map(\.path)
        XCTAssertEqual(Set(paths).count, paths.count)
        XCTAssertTrue(paths.allSatisfy { $0.hasPrefix("/") })
        XCTAssertFalse(paths.contains { $0.contains("..") })
    }

    func testDangerousExecutableAndDylibPathsRemainProbeOnly() {
        let dangerous = ArtifactCatalog.all.filter { artifact in
            artifact.path.hasSuffix(".dylib") ||
                artifact.path.hasSuffix("frida-server") ||
                artifact.path.hasSuffix("/bash") ||
                artifact.path.hasSuffix("/sh") ||
                artifact.path.hasSuffix("/ssh") ||
                artifact.path.hasSuffix("/sshd") ||
                artifact.path.contains("/LaunchDaemons/")
        }
        XCTAssertFalse(dangerous.isEmpty)
        XCTAssertTrue(dangerous.allSatisfy { $0.kind == .probeOnly })
    }

    func testEveryStrategyHasArtifacts() {
        for strategy in EnvironmentStrategy.allCases {
            XCTAssertTrue(ArtifactCatalog.all.contains { $0.strategy == strategy })
        }
    }
}
