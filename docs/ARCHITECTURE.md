# Architecture

Initial scaffold for the 404gent runtime guardrail CLI.

The event model is multimodal: prompt, command, output, image, llm, vision_observation, and os events are normalized before policy analysis. Image and VLM observations store extracted text plus forensic evidence such as image hash, source path, confidence, and visual signals. OS Guard observations store file/process metadata under `event.meta` while emitting normalized text for the existing rule engine.

The local self-loop batch is `npm run self-loop`. It reads recent `.404gent/events.jsonl` records and writes candidate policy updates to `.404gent/rule-candidates.json`.

OS Guard has two Node boundaries:

- `src/integrations/os-guard.js` converts native or simulated open/exec payloads to `type: "os"` events.
- `src/server.js` exposes `POST /os-event` on `127.0.0.1:7404` and records decisions through the shared guard pipeline.

`npm run demo:os-guard` is the local simulation path. It does not claim kernel enforcement; it emits the same normalized OS event model that the native EndpointSecurity daemon uses. Native enforcement requires Apple-approved EndpointSecurity signing and is tracked in `docs/OS_GUARD_TODO.md`.
