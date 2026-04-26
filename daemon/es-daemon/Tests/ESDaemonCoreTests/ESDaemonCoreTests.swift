import XCTest
@testable import ESDaemonCore

final class ESDaemonCoreTests: XCTestCase {
  func testWatchDefaults() {
    let client = ESClient()
    XCTAssertFalse(client.isWatching(pid: 1234))
  }

  func testWatchAll() {
    let client = ESClient(watchAll: true)
    XCTAssertTrue(client.isWatching(pid: 1234))
  }

  func testAddWatchedPID() {
    let client = ESClient()
    client.addWatchedPID(4321)
    XCTAssertTrue(client.isWatching(pid: 4321))
  }

  func testExecFromWatchedParentAddsChildPID() async {
    let client = ESClient()
    client.addWatchedPID(4321)
    await client.handleExec(argv: ["/bin/zsh", "-lc", "echo ok"], pid: 9876, parentPid: 4321, agent: "codex")
    XCTAssertTrue(client.isWatching(pid: 9876))
  }

  func testExecFromUnwatchedParentDoesNotAddChildPID() async {
    let client = ESClient()
    await client.handleExec(argv: ["/bin/zsh"], pid: 9876, parentPid: 4321, agent: "codex")
    XCTAssertFalse(client.isWatching(pid: 9876))
  }

  func testConfigFromEnvironment() {
    let config = DaemonConfig.fromEnvironment([
      "FOURGENT_POLICY_ENDPOINT": "http://127.0.0.1:9999",
      "FOURGENT_CONTROL_HOST": "127.0.0.1",
      "FOURGENT_CONTROL_PORT": "7777",
      "FOURGENT_WATCH_PIDS": "1,2, 3",
      "FOURGENT_WATCH_ALL": "true"
    ])
    XCTAssertEqual(config.policyEndpoint.absoluteString, "http://127.0.0.1:9999")
    XCTAssertEqual(config.controlPort, 7777)
    XCTAssertEqual(config.watchPIDs, [1, 2, 3])
    XCTAssertTrue(config.watchAll)
  }

  func testLocalPolicyDeniesSensitiveBasenames() {
    XCTAssertFalse(LocalPolicy.evaluateOpen(path: ".env").allow)
    XCTAssertFalse(LocalPolicy.evaluateOpen(path: "/tmp/.env.local").allow)
    XCTAssertFalse(LocalPolicy.evaluateOpen(path: "credentials.json").allow)
    XCTAssertFalse(LocalPolicy.evaluateOpen(path: "secrets.json").allow)
  }

  func testLocalPolicyDeniesSensitiveFragments() {
    XCTAssertFalse(LocalPolicy.evaluateOpen(path: "/Users/demo/.ssh/id_rsa").allow)
    XCTAssertFalse(LocalPolicy.evaluateOpen(path: "/Users/demo/.aws/credentials").allow)
    XCTAssertFalse(LocalPolicy.evaluateOpen(path: "/Users/demo/.gnupg/pubring.kbx").allow)
  }

  func testLocalPolicyAllowsOrdinaryFilesWithCache() {
    let decision = LocalPolicy.evaluateOpen(path: "/tmp/readme.txt")
    XCTAssertTrue(decision.allow)
    XCTAssertTrue(decision.cache)
  }

  func testLocalPolicyAllowsEmptyPathWithoutCache() {
    let decision = LocalPolicy.evaluateOpen(path: "")
    XCTAssertTrue(decision.allow)
    XCTAssertFalse(decision.cache)
  }

  func testControlServerRegisterPidResponse() throws {
    let client = ESClient()
    let server = try DaemonControlServer(host: "127.0.0.1", port: 0, client: client)
    let response = server.response(for: """
    POST /register-pid HTTP/1.1\r
    content-type: application/json\r
    \r
    {"pid":4567,"agent":"codex"}
    """)
    XCTAssertTrue(response.contains("\"registered\":true"))
    XCTAssertTrue(client.isWatching(pid: 4567))
  }
}
