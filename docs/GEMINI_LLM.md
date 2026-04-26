# Gemini LLM

LLM provider integration is scaffolded through `src/providers/llm.js`.

Use Anthropic/Claude review by setting an environment variable and config file:

```sh
export ANTHROPIC_API_KEY="..."
node src/cli.js --config examples/404gent.anthropic.config.json scan-image "suspicious OCR text"
```

The API key must stay outside git and outside config files. Claude review runs only when `llm.enabled` is true and the rule report decision matches `llm.reviewDecisions`.
