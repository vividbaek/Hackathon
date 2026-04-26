import Foundation
#if canImport(EndpointSecurity)
import Darwin
import EndpointSecurity
#endif

public final class ESClient {
  private var watchedPIDs: Set<Int32>
  private let watchAll: Bool
  private let bridge: PolicyBridge
  private let lock = NSLock()
  #if canImport(EndpointSecurity)
  private var esClient: OpaquePointer?
  #endif

  public init(config: DaemonConfig) {
    self.watchedPIDs = config.watchPIDs
    self.watchAll = config.watchAll
    self.bridge = PolicyBridge(endpoint: config.policyEndpoint)
  }

  public init(watchAll: Bool = false, watchedPIDs: Set<Int32> = []) {
    self.watchedPIDs = watchedPIDs
    self.watchAll = watchAll
    self.bridge = PolicyBridge(endpoint: URL(string: "http://127.0.0.1:7404")!)
  }

  public func isWatching(pid: Int32) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return watchAll || watchedPIDs.contains(pid)
  }

  public func isWatchAllEnabled() -> Bool {
    watchAll
  }

  public func addWatchedPID(_ pid: Int32) {
    lock.lock()
    defer { lock.unlock() }
    watchedPIDs.insert(pid)
  }

  public func watchedPIDList() -> [Int32] {
    lock.lock()
    defer { lock.unlock() }
    return watchedPIDs.sorted()
  }

  public func handleOpen(path: String, pid: Int32, agent: String?) async -> OpenDecision {
    guard isWatching(pid: pid) else {
      return OpenDecision(allow: true, cache: true, reason: "pid not watched")
    }
    let decision = LocalPolicy.evaluateOpen(path: path)
    _ = await bridge.postOpen(path: path, pid: pid, agent: agent, authDecision: decision)
    return decision
  }

  public func handleExec(argv: [String], pid: Int32, agent: String?) async {
    guard isWatching(pid: pid) else { return }
    _ = await bridge.postExec(argv: argv, pid: pid, agent: agent)
  }

  public func start() throws {
    #if canImport(EndpointSecurity)
    guard esClient == nil else { return }

    var client: OpaquePointer?
    let result = es_new_client(&client) { [weak self] _, message in
      guard let self else { return }
      self.handleEndpointSecurityMessage(message)
    }

    guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
      throw DaemonError.endpointSecurityClientCreateFailed(Int32(result.rawValue))
    }

    let events: [es_event_type_t] = [
      ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_NOTIFY_EXEC
    ]
    let subscribed = events.withUnsafeBufferPointer { buffer in
      es_subscribe(client, buffer.baseAddress!, UInt32(buffer.count))
    }
    guard subscribed == ES_RETURN_SUCCESS else {
      es_delete_client(client)
      throw DaemonError.endpointSecuritySubscribeFailed
    }

    esClient = client
    #else
    throw DaemonError.endpointSecurityUnavailable
    #endif
  }

  deinit {
    #if canImport(EndpointSecurity)
    if let esClient {
      es_unsubscribe_all(esClient)
      es_delete_client(esClient)
    }
    #endif
  }

  #if canImport(EndpointSecurity)
  private func handleEndpointSecurityMessage(_ message: UnsafePointer<es_message_t>) {
    switch message.pointee.event_type {
    case ES_EVENT_TYPE_AUTH_OPEN:
      handleAuthOpen(message)
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      handleNotifyExec(message)
    default:
      break
    }
  }

  private func handleAuthOpen(_ message: UnsafePointer<es_message_t>) {
    guard let esClient else { return }
    let pid = pidForProcess(message.pointee.process)
    let path = string(from: message.pointee.event.open.file.pointee.path)

    guard isWatching(pid: pid) else {
      es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, true)
      return
    }

    let decision = LocalPolicy.evaluateOpen(path: path)
    es_respond_auth_result(esClient, message, decision.allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, decision.cache)

    Task {
      _ = await bridge.postOpen(path: path, pid: pid, agent: nil, authDecision: decision)
    }
  }

  private func handleNotifyExec(_ message: UnsafePointer<es_message_t>) {
    let pid = pidForProcess(message.pointee.process)
    guard isWatching(pid: pid) else { return }

    let exec = message.pointee.event.exec
    let argv = argvForExec(exec)
    Task {
      _ = await bridge.postExec(argv: argv, pid: pid, agent: nil)
    }
  }

  private func pidForProcess(_ process: UnsafePointer<es_process_t>) -> Int32 {
    audit_token_to_pid(process.pointee.audit_token)
  }

  private func string(from token: es_string_token_t) -> String {
    guard let data = token.data else { return "" }
    return String(data: Data(bytes: data, count: token.length), encoding: .utf8) ?? ""
  }

  private func argvForExec(_ exec: es_event_exec_t) -> [String] {
    var exec = exec
    let count = es_exec_arg_count(&exec)
    var argv: [String] = []
    for index in 0..<count {
      argv.append(string(from: es_exec_arg(&exec, index)))
    }
    if argv.isEmpty {
      argv.append(string(from: exec.target.pointee.executable.pointee.path))
    }
    return argv
  }
  #endif
}

public enum DaemonError: Error, LocalizedError {
  case endpointSecurityUnavailable
  case endpointSecurityClientCreateFailed(Int32)
  case endpointSecuritySubscribeFailed

  public var errorDescription: String? {
    switch self {
    case .endpointSecurityUnavailable:
      return "EndpointSecurity is unavailable on this platform."
    case .endpointSecurityClientCreateFailed(let code):
      return "EndpointSecurity client creation failed with code \(code)."
    case .endpointSecuritySubscribeFailed:
      return "EndpointSecurity event subscription failed."
    }
  }
}
