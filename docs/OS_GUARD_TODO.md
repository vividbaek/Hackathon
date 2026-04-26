# OS Guard TODO

## Current Demo Path

`npm run demo:os-guard` is the supported demo path until Apple signing prerequisites are ready. It emits simulated OS events into the same policy, audit, vector, state, and dashboard pipeline used by the native daemon.

This simulation is intentionally not described as kernel enforcement. It demonstrates the event model and policy behavior that native EndpointSecurity will enforce.

## Native EndpointSecurity Prerequisites

- Join an Apple Developer Program team.
- Request Apple approval for `com.apple.developer.endpoint-security.client`.
- Create a valid macOS code signing identity.
- Confirm `security find-identity -v -p codesigning` returns an identity.
- Replace ad-hoc signing with a Team ID backed signature.
- Package the daemon with a provisioning profile using an app-like wrapper or migrate to a system extension.
- Grant macOS Privacy & Security permissions required by the EndpointSecurity client.

## Native Smoke Tests

- Start the Node policy server with `node src/cli.js server`.
- Run the signed daemon with `sudo FOURGENT_WATCH_PIDS=<pid> .build/debug/es-daemon`.
- Verify watched PID `.env` open is denied by `AUTH_OPEN`.
- Verify watched PID `curl` exec is recorded through `NOTIFY_EXEC`.
- Confirm `.404gent/events.jsonl` includes the corresponding `type: "os"` events.

## Follow-Up Engineering

- Track child process lineage so a watched agent's children are watched automatically.
- Add production signing, notarization, installer, and uninstaller flow.
- Improve daemon startup diagnostics for missing entitlement, invalid signing identity, and missing Privacy & Security approval.
- Decide whether to ship standalone daemon packaging or a full System Extension app bundle.
