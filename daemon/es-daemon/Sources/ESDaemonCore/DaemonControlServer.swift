import Foundation
import Network

public final class DaemonControlServer {
  private let client: ESClient
  private let listener: NWListener

  public init(host: String, port: UInt16, client: ESClient) throws {
    self.client = client
    let parameters = NWParameters.tcp
    self.listener = try NWListener(using: parameters, on: NWEndpoint.Port(rawValue: port)!)
  }

  public func start() {
    listener.newConnectionHandler = { [weak self] connection in
      connection.start(queue: .global())
      self?.handle(connection: connection)
    }
    listener.start(queue: .global())
  }

  private func handle(connection: NWConnection) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, _, _ in
      guard let self, let data, let request = String(data: data, encoding: .utf8) else {
        connection.cancel()
        return
      }
      let response = self.response(for: request)
      connection.send(content: response.data(using: .utf8), completion: .contentProcessed { _ in
        connection.cancel()
      })
    }
  }

  func response(for request: String) -> String {
    if request.hasPrefix("GET /status ") {
      return jsonResponse(status: 200, body: [
        "watchAll": client.isWatchAllEnabled(),
        "watchedPIDs": client.watchedPIDList().map(Int.init)
      ])
    }

    if request.hasPrefix("POST /register-pid ") {
      guard
        let body = request.components(separatedBy: "\r\n\r\n").last,
        let data = body.data(using: .utf8),
        let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let pidNumber = json["pid"] as? NSNumber
      else {
        return jsonResponse(status: 400, body: ["error": "register-pid requires pid"])
      }
      client.addWatchedPID(pidNumber.int32Value)
      return jsonResponse(status: 200, body: [
        "registered": true,
        "pid": pidNumber.intValue,
        "watchedPIDs": client.watchedPIDList().map(Int.init)
      ])
    }

    return jsonResponse(status: 404, body: ["error": "not found"])
  }

  private func jsonResponse(status: Int, body: [String: Any]) -> String {
    let data = (try? JSONSerialization.data(withJSONObject: body)) ?? Data("{}".utf8)
    let text = String(data: data, encoding: .utf8) ?? "{}"
    let reason = status == 200 ? "OK" : status == 400 ? "Bad Request" : "Not Found"
    return """
    HTTP/1.1 \(status) \(reason)\r
    content-type: application/json; charset=utf-8\r
    content-length: \(text.utf8.count)\r
    connection: close\r
    \r
    \(text)
    """
  }
}
