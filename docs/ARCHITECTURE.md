# Architecture

Initial scaffold for the 404gent runtime guardrail CLI.

The event model is multimodal: prompt, command, output, image, llm, and vision_observation events are normalized before policy analysis. Image and VLM observations store extracted text plus forensic evidence such as image hash, source path, confidence, and visual signals.

The local self-loop batch is `npm run self-loop`. It reads recent `.404gent/events.jsonl` records and writes candidate policy updates to `.404gent/rule-candidates.json`.
