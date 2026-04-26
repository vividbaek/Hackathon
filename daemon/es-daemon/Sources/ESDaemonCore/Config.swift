import Foundation

public struct DaemonConfig: Equatable {
  public var policyEndpoint: URL
  public var controlHost: String
  public var controlPort: UInt16
  public var watchPIDs: Set<Int32>
  public var watchAll: Bool

  public init(
    policyEndpoint: URL = URL(string: "http://127.0.0.1:7404")!,
    controlHost: String = "127.0.0.1",
    controlPort: UInt16 = 7405,
    watchPIDs: Set<Int32> = [],
    watchAll: Bool = false
  ) {
    self.policyEndpoint = policyEndpoint
    self.controlHost = controlHost
    self.controlPort = controlPort
    self.watchPIDs = watchPIDs
    self.watchAll = watchAll
  }

  public static func fromEnvironment(_ environment: [String: String] = ProcessInfo.processInfo.environment) -> DaemonConfig {
    let endpoint = environment["FOURGENT_POLICY_ENDPOINT"].flatMap(URL.init(string:))
      ?? URL(string: "http://127.0.0.1:7404")!
    let host = environment["FOURGENT_CONTROL_HOST"] ?? "127.0.0.1"
    let port = environment["FOURGENT_CONTROL_PORT"].flatMap(UInt16.init) ?? 7405
    let watchAll = parseBool(environment["FOURGENT_WATCH_ALL"])
    let pids = Set((environment["FOURGENT_WATCH_PIDS"] ?? "")
      .split(separator: ",")
      .compactMap { Int32($0.trimmingCharacters(in: .whitespacesAndNewlines)) })

    return DaemonConfig(
      policyEndpoint: endpoint,
      controlHost: host,
      controlPort: port,
      watchPIDs: pids,
      watchAll: watchAll
    )
  }

  private static func parseBool(_ value: String?) -> Bool {
    guard let value else { return false }
    return ["1", "true", "yes", "on"].contains(value.lowercased())
  }
}
