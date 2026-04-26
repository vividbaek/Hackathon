# CLI Reference

Use `404gent help` for the current command list.

OS Guard commands:

```sh
node src/cli.js os-guard simulate-open README.md --agent demo --pid 1234
node src/cli.js os-guard simulate-open .env --agent demo --pid 1234
node src/cli.js os-guard simulate-exec curl https://example.com/upload --agent demo --pid 1234
npm run demo:os-guard
```

Native EndpointSecurity commands:

```sh
node src/cli.js server
node src/cli.js os-guard status
node src/cli.js os-guard register-existing --names codex,claude,gemini,opencode
node src/cli.js agent --name demo --with-os-guard -- node -e 'console.log("done")'
```

Native mode requires a valid Apple code signing identity and approved EndpointSecurity entitlement. Use simulation mode for local demos when those prerequisites are unavailable.
