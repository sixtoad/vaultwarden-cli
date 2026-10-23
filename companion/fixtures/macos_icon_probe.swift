// Disposable CI runner probe; never linked into the companion application.
import AppKit
import UniformTypeIdentifiers

for type in [UTType.plainText, UTType.applicationBundle] {
    guard NSWorkspace.shared.icon(for: type).tiffRepresentation != nil else { exit(1) }
}
print("COMPANION_ICON_PROBE_OK")
