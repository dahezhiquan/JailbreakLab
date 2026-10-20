import SwiftUI

@main
struct JailbreakLabApp: App {
    @StateObject private var store = SimulationStore()

    var body: some Scene {
        WindowGroup {
            DashboardView()
                .environmentObject(store)
                .preferredColorScheme(.dark)
        }
    }
}
