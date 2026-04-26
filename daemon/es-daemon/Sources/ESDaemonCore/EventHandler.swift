import Foundation

public struct EventHandler {
  private let client: ESClient

  public init(client: ESClient) {
    self.client = client
  }

  public func handleOpen(path: String, pid: Int32, agent: String? = nil) async -> OpenDecision {
    await client.handleOpen(path: path, pid: pid, agent: agent)
  }

  public func handleExec(argv: [String], pid: Int32, agent: String? = nil) async {
    await client.handleExec(argv: argv, pid: pid, agent: agent)
  }
}
