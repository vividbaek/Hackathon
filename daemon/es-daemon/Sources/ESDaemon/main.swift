import ESDaemonCore
import Foundation

let config = DaemonConfig.fromEnvironment()
let client = ESClient(config: config)

do {
  let control = try DaemonControlServer(host: config.controlHost, port: config.controlPort, client: client)
  control.start()
  do {
    try client.start()
  } catch {
    fputs("es-daemon warning: \(error.localizedDescription)\n", stderr)
  }
  print("es-daemon control listening on \(config.controlHost):\(config.controlPort)")
  RunLoop.main.run()
} catch {
  fputs("es-daemon failed: \(error.localizedDescription)\n", stderr)
  exit(1)
}
