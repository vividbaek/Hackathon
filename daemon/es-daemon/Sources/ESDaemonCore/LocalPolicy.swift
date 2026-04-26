import Foundation

public struct OpenDecision: Equatable {
  public let allow: Bool
  public let cache: Bool
  public let reason: String
}

public enum LocalPolicy {
  private static let denyBasenames: Set<String> = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "credentials.json",
    "secrets.json"
  ]

  private static let denyFragments = [
    "/.ssh/",
    "/.aws/",
    "/.gnupg/"
  ]

  public static func evaluateOpen(path: String?) -> OpenDecision {
    guard let path, !path.isEmpty else {
      return OpenDecision(allow: true, cache: false, reason: "empty path")
    }

    let normalized = path.replacingOccurrences(of: "\\", with: "/")
    let basename = URL(fileURLWithPath: normalized).lastPathComponent
    if denyBasenames.contains(basename) {
      return OpenDecision(allow: false, cache: false, reason: "sensitive file: \(basename)")
    }

    if let fragment = denyFragments.first(where: { normalized.contains($0) }) {
      return OpenDecision(allow: false, cache: false, reason: "sensitive path: \(fragment)")
    }

    if normalized.hasSuffix("/.kube/config") || basename == ".npmrc" || basename == ".pypirc" || basename == ".netrc" {
      return OpenDecision(allow: false, cache: false, reason: "sensitive config: \(basename)")
    }

    return OpenDecision(allow: true, cache: true, reason: "allowed")
  }
}
