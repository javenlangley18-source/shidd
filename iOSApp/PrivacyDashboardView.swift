import SwiftUI

struct PrivacyDashboardView: View {
    @State private var filterEnabled = false

    private let capabilities = [
        ("Location", "location.fill"),
        ("Camera", "camera.fill"),
        ("Microphone", "mic.fill"),
        ("Photos", "photo.fill")
    ]

    var body: some View {
        NavigationStack {
            List {
                Section("Network protection") {
                    Toggle("Block known trackers", isOn: $filterEnabled)
                    Text("Filtering is handled locally by the Network Extension.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("This app") {
                    ForEach(capabilities, id: \.0) { capability in
                        Label(capability.0, systemImage: capability.1)
                    }
                }

                Section {
                    Link("Review privacy settings", destination: URL(string: "App-prefs:root=Privacy")!)
                }
            }
            .navigationTitle("Privacy Shield")
        }
    }
}

#Preview {
    PrivacyDashboardView()
}