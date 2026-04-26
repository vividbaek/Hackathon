import Foundation

public struct PolicyDecision: Decodable, Equatable {
  public let decision: String
  public let reason: String?
}

public final class PolicyBridge {
  private let endpoint: URL
  private let session: URLSession

  public init(endpoint: URL, session: URLSession = .shared) {
    self.endpoint = endpoint
    self.session = session
  }

  public func postOpen(path: String, pid: Int32, agent: String?, authDecision: OpenDecision) async -> PolicyDecision {
    var payload: [String: Any] = [
      "type": "open",
      "path": path,
      "pid": Int(pid),
      "authDecision": authDecision.allow ? "allow" : "deny",
      "reason": authDecision.reason,
      "cache": authDecision.cache
    ]
    if let agent { payload["agent"] = agent }
    return await post(payload: payload)
  }

  public func postExec(argv: [String], pid: Int32, agent: String?) async -> PolicyDecision {
    var payload: [String: Any] = [
      "type": "exec",
      "argv": argv,
      "pid": Int(pid)
    ]
    if let agent { payload["agent"] = agent }
    return await post(payload: payload)
  }

  private func post(payload: [String: Any]) async -> PolicyDecision {
    do {
      var request = URLRequest(url: endpoint.appendingPathComponent("os-event"))
      request.httpMethod = "POST"
      request.setValue("application/json", forHTTPHeaderField: "content-type")
      request.httpBody = try JSONSerialization.data(withJSONObject: payload)
      let (data, _) = try await session.data(for: request)
      return (try? JSONDecoder().decode(PolicyDecision.self, from: data))
        ?? PolicyDecision(decision: "unknown", reason: "unparseable policy response")
    } catch {
      return PolicyDecision(decision: "error", reason: error.localizedDescription)
    }
  }
}
