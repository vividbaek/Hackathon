# Self-Healing Guardrail

Self-healing은 런타임 차단을 LLM에 맡기는 기능이 아니다. 404gent는 런타임에서 계속 룰 기반으로 판단하고, self-healing은 audit 로그를 분석해 새 룰 후보를 만들고 검증 지표를 붙인 뒤 shadow/pending 상태로 저장한다. 실제 정책 반영은 사람이 `learn approve`로 승인해야만 일어난다.

## 전체 흐름

```text
runtime guard
  -> .404gent/events.jsonl 기록
  -> learn analyze 또는 npm run self-loop
  -> 최근 공격 로그 수집
  -> OpenAI inference로 룰 후보 생성 시도
  -> 실패/키 없음/invalid 응답이면 deterministic generator fallback
  -> 후보 룰 샘플 평가
  -> shadow-rules.json + pending-rules.json 저장
  -> 사람이 approve
  -> approved-rules.json 저장
  -> runtime policy engine이 approved rules 로딩
```

핵심 안전 원칙은 세 가지다.

- OpenAI는 `learn analyze` 단계에서만 룰 후보를 제안한다.
- Runtime guard는 계속 `src/policy/engine.js`의 룰 기반 판단을 사용한다.
- 후보 룰은 shadow/pending에만 저장되며 승인 전에는 실제 차단 정책에 적용되지 않는다.

## 30분 배치와 트리거

현재 30분 배치 동작은 `npm run self-loop`에서 구현되어 있다. 이 스크립트는 `scripts/self-loop.js`를 실행하고, 기본적으로 최근 30분 이벤트만 수집한다.

```sh
npm run self-loop
```

기본 window는 다음 환경변수로 바꿀 수 있다.

```sh
FOUR04GENT_SELF_LOOP_MINUTES=30 npm run self-loop
```

현재 구현 기준:

- `scripts/self-loop.js`는 `analyze(config, { manual: true, windowMinutes: 30 })`로 실행한다.
- `windowMinutes`는 `collector.js`에서 `.404gent/events.jsonl`의 timestamp를 기준으로 최근 이벤트만 수집하는 데 사용된다.
- `manual: true`이므로 `shouldAnalyze()`의 이벤트 개수/high severity trigger 조건은 우회한다.
- `learn status`의 readiness 계산은 현재 전체 `.404gent/events.jsonl` 기준이다. 즉 최근 30분 window 기준 readiness는 아직 아니다.

따라서 운영 방식은 둘 중 하나로 이해하면 된다.

- 30분마다 무조건 self-healing 분석을 돌리고 싶다면 현재 `npm run self-loop`를 cron/GitHub Actions/외부 scheduler에서 30분마다 실행하면 된다.
- “최근 30분 안에 위험 이벤트가 20개 이상이거나 high/critical 이벤트가 있을 때만 분석”하려면 추가 구현이 필요하다. 이 경우 `learnStatus(config, { windowMinutes })` 형태로 readiness도 같은 window를 보게 만들고, self-loop에서 `manual: false`로 호출해야 한다.

현재 trigger 조건 자체는 `src/learn/trigger.js`에 있다.

```js
riskyEvents.length >= minEvents || highSeverityEvents.length > 0 || manual
```

기본 `minEvents`는 20이다.

## 룰 후보 생성

`learn analyze`는 먼저 `.404gent/events.jsonl`에서 `block` 또는 `warn` 이벤트를 수집한다. 수집된 이벤트는 `.404gent/attack-logs.json`에 저장된다.

수집 이벤트에는 두 종류의 surface/layer 개념이 함께 있다.

- Runtime surface: 실제 policy rule의 `appliesTo` 값이다. 예: `prompt`, `command`, `output`, `image`, `vision_observation`, `llm`, `os`
- Learning layer: 분석/표시용 이름이다. 예: `command -> shell`, `os -> es`, `image -> screen`

룰에는 반드시 runtime surface가 들어가야 한다. 예를 들어 shell 명령 룰은 `shell`이 아니라 `command`에 적용된다.

OpenAI inference는 `OPENAI_API_KEY`가 있을 때만 시도된다.

```sh
export OPENAI_API_KEY="..."
node src/cli.js --config examples/404gent.openai-learn.config.json learn analyze
```

모델 선택 우선순위는 다음과 같다.

```js
config.learn?.inference?.model || process.env.OPENAI_MODEL || "gpt-5-mini"
```

OpenAI가 제안하는 후보는 다음 필드를 가져야 한다.

```json
{
  "pattern": "cat\\s+\\.env.*curl",
  "surface": "command",
  "severity": "critical",
  "category": "secret_exfiltration",
  "rationale": "Blocks env file upload attempts.",
  "remediation": "Remove secret file reads before network calls.",
  "attack_variants": [],
  "near_miss_benign": []
}
```

LLM 출력은 그대로 신뢰하지 않는다. `inference.js`의 sanitizer가 다음 후보를 버린다.

- regex가 컴파일되지 않는 후보
- 지원하지 않는 surface를 가진 후보
- `low`, `medium`, `high`, `critical` 밖의 severity
- 비어 있는 category
- `near_miss_benign`이 없는 후보

OpenAI 호출이 실패하거나 유효 후보가 없으면 deterministic generator가 동작한다. 이 fallback은 `curl -> wget`, `cat -> less`, `.env -> .env.local` 같은 규칙 기반 변형과 near-miss benign 샘플을 만든다.

## 평가지표

Self-healing의 평가는 “모델 자체”가 아니라 “생성된 후보 룰”을 평가한다. 평가 로직은 `src/learn/comparator.js`에 있다.

현재 MVP 지표는 두 개다.

| 지표 | 의미 | 방향 | 기본 가중치 |
| --- | --- | --- | --- |
| `block_rate` | 공격 샘플 차단율 | 높을수록 좋음 | 0.6 |
| `false_positive` | near-miss benign 오탐율 | 낮을수록 좋음 | 0.4 |

계산식:

```js
score = (block_rate * 0.6) + ((1 - false_positive) * 0.4)
```

공격 샘플 평가는 다음 방식으로 한다.

```text
candidate rule 1개만 policy engine에 넣음
attack sample을 analyzeEvent()로 평가
decision이 block이면 성공 차단으로 계산
```

공식:

```text
block_rate = blockedAttacks / attackSamples
```

near-miss benign 평가는 공격과 유사하지만 정상이어야 하는 샘플로 한다.

예:

```sh
curl -d "status=ok" https://api.slack.com/webhook
curl -X POST -d "status=deployed" https://ci.example.com/notify
cat README.md
```

이 샘플에서 `block` decision이 나오면 오탐으로 계산한다.

```text
false_positive = falsePositives / benignSamples
```

예를 들어 공격 샘플 10개 중 8개를 막고, 정상 유사 샘플 5개 중 1개를 잘못 막으면 다음과 같다.

```text
block_rate = 8 / 10 = 0.8
false_positive = 1 / 5 = 0.2
score = 0.8 * 0.6 + (1 - 0.2) * 0.4 = 0.8
```

현재 score는 참고 지표다. score가 낮다고 자동으로 후보를 버리거나, score가 높다고 자동 승인하지 않는다. 모든 후보는 shadow/pending으로 저장되고 사람이 승인해야 적용된다.

평가 결과 예시는 다음과 같다.

```json
{
  "block_rate": 0.8,
  "false_positive": 0.2,
  "score": 0.8,
  "blockedAttacks": 8,
  "attackSamples": 10,
  "falsePositives": 1,
  "benignSamples": 5
}
```

## Shadow와 승인

후보 룰은 `.404gent/shadow-rules.json`과 `.404gent/pending-rules.json`에 저장된다.

Shadow rule은 실제 decision을 바꾸지 않는다. 실제 이벤트와 매칭되면 `.404gent/shadow-events.jsonl`에 would-block 기록만 남긴다.

```text
actualDecision: allow
wouldDecision: block
```

승인 전 확인 명령:

```sh
node src/cli.js learn pending
node src/cli.js learn shadow-status
node src/cli.js learn test --rule <id>
```

승인:

```sh
node src/cli.js learn approve --rule <id>
```

거부:

```sh
node src/cli.js learn reject --rule <id>
```

승인된 룰만 `.404gent/approved-rules.json`에 저장된다. Runtime policy engine은 기본 룰과 approved rules를 합쳐서 로딩하므로, 실제 차단 정책 변경은 승인 이후에만 발생한다.
