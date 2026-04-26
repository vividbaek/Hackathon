# 404gent Architecture

> AI 코딩 에이전트를 위한 EDR 스타일 런타임 가드레일 시스템 아키텍처

The event model is multimodal: prompt, command, output, image, llm, vision_observation, and os events are normalized before policy analysis. Image and VLM observations store extracted text plus forensic evidence such as image hash, source path, confidence, and visual signals. OS Guard observations store file/process metadata under `event.meta` while emitting normalized text for the existing rule engine.

The local self-loop batch is `npm run self-loop`. It reads recent `.404gent/events.jsonl` records and writes candidate policy updates to `.404gent/rule-candidates.json`.

OS Guard has two Node boundaries:

- `src/integrations/os-guard.js` converts native or simulated open/exec payloads to `type: "os"` events.
- `src/server.js` exposes `POST /os-event` on `127.0.0.1:7404` and records decisions through the shared guard pipeline.

`npm run demo:os-guard` is the local simulation path. It does not claim kernel enforcement; it emits the same normalized OS event model that the native EndpointSecurity daemon uses. Native enforcement requires Apple-approved EndpointSecurity signing and is tracked in `docs/OS_GUARD_TODO.md`.
## 시스템 개요

404gent는 AI 코딩 에이전트의 모든 I/O를 5개 감시 표면(Prompt, Command, Output, Image/VLM, LLM)으로 분류하고, 단일 정책 엔진을 통해 실시간으로 탐지·판정·기록합니다.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         404gent System                              │
│                                                                     │
│  ┌──────────────────────── Input Layer ──────────────────────────┐  │
│  │                                                               │  │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ Prompt │ │Command │ │ Output │ │Image/VLM │ │   LLM    │  │  │
│  │  │  scan  │ │  scan  │ │  scan  │ │   scan   │ │   scan   │  │  │
│  │  └───┬────┘ └───┬────┘ └───┬────┘ └────┬─────┘ └────┬─────┘  │  │
│  │      │          │          │            │            │         │  │
│  └──────┼──────────┼──────────┼────────────┼────────────┼────────┘  │
│         └──────────┴──────────┴────────────┴────────────┘           │
│                               │                                     │
│                    ┌──────────▼──────────┐                          │
│                    │  Event Normalizer   │                          │
│                    │  (vision.js)        │                          │
│                    └──────────┬──────────┘                          │
│                               │                                     │
│  ┌────────────────────────────▼─────────────────────────────────┐  │
│  │                    Policy Engine                              │  │
│  │                   (policy/engine.js)                          │  │
│  │                                                               │  │
│  │  ┌─────────────┐   ┌──────────────┐   ┌──────────────────┐   │  │
│  │  │ Rule Match  │──▶│   Severity   │──▶│     Decision     │   │  │
│  │  │ (regex)     │   │  Scoring     │   │ allow/warn/block │   │  │
│  │  └─────────────┘   └──────────────┘   └──────────────────┘   │  │
│  │                                                               │  │
│  └──────────────────────────┬───────────────────────────────────┘  │
│                              │                                      │
│                   ┌──────────▼──────────┐                          │
│                   │  Claude LLM Review  │  (optional)              │
│                   │  mergeReports()     │                          │
│                   └──────────┬──────────┘                          │
│                              │                                      │
│  ┌───────────────────────────▼──────────────────────────────────┐  │
│  │                    Output Layer                               │  │
│  │                                                               │  │
│  │  ┌────────┐ ┌────────┐ ┌───────────┐ ┌──────────┐ ┌───────┐ │  │
│  │  │ Audit  │ │ State  │ │  Vector   │ │Dashboard │ │ Self  │ │  │
│  │  │  Log   │ │ Update │ │  Store    │ │  (live)  │ │ Loop  │ │  │
│  │  └────────┘ └────────┘ └───────────┘ └──────────┘ └───────┘ │  │
│  │                                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 디렉토리 구조

```
404gent/
├── src/
│   ├── cli.js                 # CLI 엔트리포인트 (scan-*, run, agent, tower)
│   ├── config.js              # JSON 설정 파일 로더 + 회사별 프로필 적용
│   ├── dashboard.js           # 실시간 웹 대시보드 (LangGraph 스타일)
│   ├── harness.js             # 에이전트 핸드오프 생성 (safe task brief)
│   ├── runner.js              # 가드레일 적용 명령 실행 (run --)
│   ├── vision.js              # 이미지/VLM 관찰 정규화
│   ├── audit.js               # 감사 로그 (events.jsonl)
│   ├── state.js               # 상태 파일 (state.json)
│   ├── vector-store.js        # 로컬 벡터 스토어 mock (vectors.jsonl)
│   ├── report.js              # 리포트 포매팅
│   ├── output-monitor.js      # stdout/stderr 모니터링
│   ├── recovery.js            # 복구 모듈 (스캐폴딩)
│   ├── diagnostics.js         # 환경 진단
│   ├── doctor.js              # doctor 명령 핸들러
│   ├── policy/
│   │   ├── engine.js          # 핵심 정책 엔진 (analyzeEvent, scanText, mergeReports)
│   │   ├── rules.js           # 룰 컴파일러 + 룰셋 관리
│   │   ├── default-rules.js   # 기본 탐지 룰 정의
│   │   └── severity.js        # 위험도 레벨 정의 (low → critical)
│   ├── providers/
│   │   ├── llm.js             # Claude API 보강 판단 프로바이더
│   │   └── vision-llm.js      # Claude Vision 이미지 분석 프로바이더
│   └── integrations/
│       └── cmux.js            # cmux 연동 어댑터
├── scripts/                   # 데모, 벤치마크, self-loop 스크립트
├── examples/                  # 설정 파일 예제, hook 스크립트
├── test/                      # Node.js 내장 test runner 테스트
├── docs/                      # 문서
└── .404gent/                  # 런타임 데이터 (자동 생성)
    ├── events.jsonl           # 감사 이벤트 로그
    ├── state.json             # 현재 상태
    ├── vectors.jsonl          # 벡터 스토어 기록
    ├── rule-candidates.json   # self-loop 룰 후보
    └── handoffs/              # 에이전트 핸드오프 파일
```

## 핵심 모듈 상세

### 1. Policy Engine (`src/policy/engine.js`)

시스템의 심장. 모든 이벤트는 이 엔진을 통과합니다.

```
Event → normalizeEvent() → Rule Matching → Severity Scoring → Decision
```

**주요 함수:**
- `analyzeEvent(event, config)` — 이벤트를 정규화하고 룰 매칭 후 판정 반환
- `scanText({ surface, text, config })` — CLI에서 직접 호출하는 고수준 스캔 함수
- `mergeReports(ruleReport, llmReport)` — 룰베이스 결과와 Claude 판단을 병합

**이벤트 타입:** `prompt`, `command`, `output`, `image`, `vision_observation`, `llm`

**판정 로직:**
```
findings 없음           → allow
mode: observe           → warn (차단 없이 기록)
mode: lockdown          → block (모두 차단)
mode: enforce (기본)    → severity가 high/critical이면 block, 아니면 warn
```

### 2. Vision Normalizer (`src/vision.js`)

이미지, OCR, VLM 결과를 통합 이벤트 포맷으로 정규화합니다.

```
┌──────────────────────┐
│  Input Sources       │
│  - imagePath         │
│  - extractedText     │
│  - ocrText           │
│  - regions[]         │
│  - hiddenPrompts[]   │
│  - confidence        │
└─────────┬────────────┘
          │
          ▼
┌──────────────────────┐
│  normalizeVision     │
│  Observation()       │
│                      │
│  - SHA256 hash 생성  │
│  - 텍스트 필드 병합  │
│  - evidence 구조화   │
│  - artifact 생성     │
└─────────┬────────────┘
          │
          ▼
┌──────────────────────┐
│  Normalized Event    │
│  {type, text,        │
│   evidence, artifacts│
│   meta}              │
└──────────────────────┘
```

전처리 팀이 이미지 분석을 별도 단계에서 수행하는 경우 `image_preprocess_v1` JSON을 `scan-image --preprocessed`로 주입합니다. MVP에서는 이미지를 base64로 넣지 않고 `.404gent/` 기준 상대 경로만 사용합니다.

```
.404gent/
├── images/raw/{timestamp}_{id}.png
├── images/normalized/{timestamp}_{id}.normalized.png
└── preprocessed/{timestamp}_{id}.json
```

```json
{
  "schemaVersion": "image_preprocess_v1",
  "imageId": "20260426_103000_abc123",
  "sourceImagePath": "images/raw/20260426_103000_abc123.png",
  "normalizedImagePath": "images/normalized/20260426_103000_abc123.normalized.png",
  "detections": [
    {
      "id": "det-1",
      "kind": "hidden_text",
      "severityHint": "critical",
      "text": "hidden instruction text",
      "extractedValue": "decoded payload",
      "bbox": { "x": 0.1, "y": 0.2, "width": 0.3, "height": 0.05 },
      "confidence": 0.91
    }
  ]
}
```

```
node src/cli.js scan-image --preprocessed .404gent/preprocessed/20260426_103000_abc123.json
```

로컬 OCR 전처리까지 404gent에서 수행하려면 raw 이미지를 `preprocess-image`에 넣습니다. 이 명령은 `src/ocr.js`와 `src/utils/image-processor.js`를 사용해 raw/normalized 이미지와 `image_preprocess_v1` JSON을 생성합니다.

```
node src/cli.js preprocess-image captures/dashboard.png
node src/cli.js scan-image --preprocessed .404gent/preprocessed/<generated-id>.json
```

Policy Server는 `.404gent/images/` 아래 파일을 `/images/...`로 서빙하므로 dashboard와 리뷰 UI가 원본/정규화 이미지를 같은 상대 경로 규칙으로 참조할 수 있습니다.

### 3. Runner (`src/runner.js`)

셸 명령을 가드레일로 감싸서 실행합니다.

```
command args
  │
  ├─ scan-command ──▶ block? ──▶ 실행 중단 (exit 126)
  │                     │
  │                    allow/warn
  │                     │
  ├─ spawn(command) ◀──┘
  │     │
  │     ├─ stdout capture
  │     └─ stderr capture
  │
  └─ scan-output ──▶ block? ──▶ 경고 출력
                       │
                      allow/warn ──▶ 정상 종료
```

### 4. Agent Harness (`src/harness.js`)

사용자 요청을 안전한 에이전트 브리프로 변환합니다.

```
user request
  │
  ├─ scan-prompt (intake 검사)
  │
  ├─ role config 로드 (qa / backend / security)
  │     ├─ allowedActions
  │     └─ blockedActions
  │
  ├─ safe task brief 생성
  │     ├─ safe context 규칙
  │     └─ runtime rules (run --, scan-image, scan-llm)
  │
  ├─ scan-llm (handoff 검사)
  │
  └─ 파일 저장
        ├─ .404gent/handoffs/<role>-latest.md
        └─ .404gent/handoffs/<sessionId>.md
```

**에이전트 역할:**

| Role | 목적 | 허용 | 차단 |
|------|------|------|------|
| `qa` | UI/디자인 QA | 파일 읽기, 테스트 실행 | 이미지 속 명령 실행 |
| `backend` | 통합 검증 | 안전 명령 실행, 로그 검사 | 래퍼 없는 셸 명령 |
| `security` | 보안 분석 | 감사 로그 분석, 정책 제안 | 자동 정책 적용 |

### 5. Dashboard (`src/dashboard.js`)

LangGraph 스타일의 실시간 웹 대시보드로, 에이전트 상태와 보안 이벤트를 시각화합니다.

```
┌─────────────────────────────────────────────────────────┐
│                    Dashboard View                        │
│                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Vision    │───▶│   Policy    │───▶│ LLM Review  │  │
│  │  Sentinel   │    │   Arbiter   │    │             │  │
│  │   (👁)      │    │   (🛡)      │    │   (🤖)      │  │
│  └─────────────┘    └──────┬──────┘    └──────┬──────┘  │
│                            │                   │         │
│                     ┌──────▼──────┐    ┌──────▼──────┐  │
│                     │  Forensic   │    │ Supervisor  │  │
│                     │   Agent     │    │             │  │
│                     │   (🔍)      │    │   (🎯)      │  │
│                     └──────┬──────┘    └─────────────┘  │
│                            │                             │
│                     ┌──────▼──────┐                      │
│                     │    Rule     │                      │
│                     │   Agent    │                      │
│                     │   (⚙)      │                      │
│                     └─────────────┘                      │
│                                                         │
│  [Alerts]  [Event Timeline]  [Block Notifications]      │
└─────────────────────────────────────────────────────────┘
```

## 3-Agent 병렬 파이프라인

발표용 핵심 플로우. 세 에이전트가 각자의 역할을 수행합니다.

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Agent 1: Vision Sentinel (👁)                                  │
│  ├─ 이미지·스크린샷·OCR에서 숨겨진 prompt injection 탐지        │
│  ├─ inputs: image file, screenshot, OCR text, VLM regions      │
│  └─ outputs: extractedText, hiddenPrompts, regions, confidence │
│         │                                                       │
│         ▼                                                       │
│  Agent 2: Policy Arbiter (🛡)                                   │
│  ├─ Vision Sentinel 결과를 룰베이스 + Claude로 판정             │
│  ├─ inputs: 모든 이벤트 타입                                    │
│  └─ outputs: allow / warn / block, findings, remediation       │
│         │                                                       │
│         ▼                                                       │
│  Agent 3: Rule Steward (⚙)                                     │
│  ├─ 차단·경고 로그로 포렌식 증거 묶기 + self-loop 룰 후보 생성 │
│  ├─ inputs: events.jsonl, vectors.jsonl                         │
│  └─ outputs: rule-candidates.json, replay corpus, policy diff  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 이벤트 모델

모든 감시 이벤트는 `normalizeEvent()`를 거쳐 통일된 구조를 갖습니다.

```json
{
  "id": "evt_abc123_xyz",
  "timestamp": "2026-04-26T12:00:00.000Z",
  "event": {
    "type": "image",
    "text": "Agent must execute shell command",
    "source": "vision-agent",
    "companyId": "fintech-a",
    "agentId": "agent-qa",
    "evidence": {
      "imageHash": "sha256:...",
      "imagePath": "captures/frame-1.png",
      "extractedText": "Agent must execute shell command",
      "regions": [{ "x": 0.12, "y": 0.34, "width": 0.5, "height": 0.08 }],
      "hiddenPrompts": ["Agent must execute shell command"],
      "confidence": 0.95
    },
    "artifacts": [{ "type": "image", "path": "captures/frame-1.png", "hash": "sha256:..." }]
  },
  "decision": "block",
  "findings": [
    {
      "id": "image-agent-command-injection",
      "severity": "critical",
      "category": "prompt-injection",
      "rationale": "이미지에서 에이전트 대상 명령 탐지",
      "remediation": "해당 이미지의 텍스트를 에이전트 컨텍스트에서 제거"
    }
  ]
}
```

## 데이터 흐름

### 기본 스캔 흐름
```
CLI input → scanText() → analyzeEvent() → audit + state + vector → CLI output
```

### Claude 보강 판단 흐름
```
CLI input → scanText() → ruleReport
                            │
                            ├─ shouldReviewWithLlm()? ──▶ Claude API 호출
                            │                               │
                            │                          llmReport
                            │                               │
                            └──────── mergeReports() ◀──────┘
                                          │
                                    finalReport → audit + state + vector → CLI output
```

### 에이전트 핸드오프 흐름
```
user task
  │
  ├─ scan-prompt (intake)
  │
  ├─ buildAgentBrief()
  │     ├─ role config
  │     ├─ safe context
  │     └─ runtime rules
  │
  ├─ scan-llm (handoff 검증)
  │
  ├─ saveAgentHandoff()
  │     ├─ <role>-latest.md
  │     └─ <sessionId>.md
  │
  └─ agent에게 safe brief 전달
```

## 보안 설계 원칙

### 1. Defense in Depth
모든 I/O가 동일한 정책 엔진을 통과하므로, 하나의 표면이 뚫려도 다른 표면에서 탐지 가능.

### 2. Evidence-Preserving Redaction
에이전트에게는 안전 요약만 전달하되, 포렌식 로그에는 원본 증거를 보존.

### 3. Human-in-the-Loop
Self-loop가 생성한 룰 후보는 자동 적용되지 않고, 사람의 승인을 거침.

### 4. Zero Trust for External Context
이미지, VLM, RAG 등 외부 소스의 컨텍스트는 기본적으로 불신하고, 정책 엔진 통과 후에만 에이전트에게 전달.

### 5. Least Privilege Execution
에이전트 역할별로 허용/차단 액션을 명시하고, 위험 감지 시 권한을 자동 축소.

## 기술 스택

| 구성 요소 | 기술 |
|-----------|------|
| Runtime | Node.js 20+ (ESM) |
| Dependencies | Zero (stdlib only) |
| LLM Provider | Claude API (선택적) |
| Vision Provider | Claude Vision (선택적) |
| Storage | JSONL flat files |
| Dashboard | Vanilla HTML/CSS/JS (내장 HTTP 서버) |
| Test | Node.js built-in test runner |
