# 404gent

> AI 코딩 에이전트를 위한 실시간 보안 가드레일

AI 에이전트(Claude Code, Cursor 등)가 프롬프트를 받고, 명령을 실행하고, 출력을 해석하는 **모든 단계에서 위험을 탐지하고 차단**합니다.

## 문제

- 이미지 속 숨겨진 텍스트가 에이전트를 조종할 수 있음
- `rm -rf /` 같은 위험 명령이 필터 없이 실행될 수 있음
- 에이전트가 시크릿/환경변수를 외부로 노출할 수 있음
- LLM 간 핸드오프에서 악성 지시가 전파될 수 있음

## 감시 표면

| Surface | 무엇을 검사하나 | 예시 |
|---------|-----------------|------|
| **Prompt** | 에이전트에 전달되는 프롬프트 | `ignore previous instructions...` |
| **Command** | 실행 전 셸 명령 | `rm -rf /`, `curl attacker.com` |
| **Output** | stdout/stderr 출력 | `AWS_SECRET_ACCESS_KEY=...` |
| **Image** | 이미지/PDF 속 숨겨진 텍스트, QR 코드 | 스크린샷 속 숨겨진 명령 |
| **LLM** | 에이전트 간 핸드오프, RAG 컨텍스트 | 악성 지시가 포함된 메모리 |

## 아키텍처

```
                       ┌──────────────────────┐
                       │   Text Inputs        │
                       │ prompt / command     │
                       │ output / llm context │
                       └──────────┬───────────┘
                                  │
                       ┌──────────▼───────────┐
                       │ Normalize Event      │
                       └──────────┬───────────┘
                                  │
  ┌───────────────────────┐       │
  │   Image Inputs        │       │
  │ screenshot / image    │       │
  │ OCR / VLM result      │       │
  └──────────┬────────────┘       │
             │                    │
  ┌───────────────────────┐       │
  │ Vision Sentinel Role  │       │
  │ extract hidden text   │       │
  │ suspicious regions    │       │
  └──────────┬────────────┘       │
             │                    │
             └──────────┬─────────┘
                        ▼
          ┌──────────────────────────────┐
          │      Merge & Classify        │
          └──────────────┬───────────────┘
                         ▼
          ┌──────────────────────────────┐
          │ Policy Engine                │
          │ rules + severity + mode      │
          └──────────────┬───────────────┘
                         ▼
                ┌─────────────────┐
                │ allow/warn/block│
                └────────┬────────┘
                         ▼
          ┌──────────────────────────────┐
          │ Audit / State / Vector Store │
          │ Evidence Logs                │
          └──────────────┬───────────────┘
                         ▼
          ┌──────────────────────────────┐
          │ Dashboard                    │
          │ live status + alerts         │
          └──────────────┬───────────────┘
                         ▼
          ┌──────────────────────────────┐
          │ Rule Steward Role            │
          │ 30-min Self-Healing Loop     │
          └──────────────┬───────────────┘
                         ▼
          ┌──────────────────────────────┐
          │ Candidate → Shadow → Pending │
          │ → Approved Rule              │
          └──────────────┬───────────────┘
                         ▼
          ┌──────────────────────────────┐
          │ Updated Guardrail            │
          └──────────────────────────────┘
```

## 핵심 기능

- **멀티모달 탐지** — 텍스트, 이미지(OCR), PDF, QR 코드를 하나의 정책 엔진으로 검사
- **3-Agent 파이프라인** — Vision Sentinel → Policy Arbiter → Rule Steward
- **Self-healing 룰** — 탐지 로그 기반으로 자동 룰 후보 생성, 사람 승인 후 적용
- **실시간 대시보드** — 보안 이벤트, 에이전트 상태, 룰 후보를 한눈에 확인
- **운영 모드** — `observe`(경고만) / `enforce`(기본, 위험 차단) / `lockdown`(모두 차단)

## 빠른 시작

```sh
npm install

# 명령어 검사
node src/cli.js scan-command "rm -rf /"

# 출력 검사
node src/cli.js scan-output "AWS_SECRET_ACCESS_KEY=example"

# 이미지/PDF 스캔 (숨겨진 텍스트 + QR 코드 탐지)
node src/ocr.js examples/test_samples/poster_attack_scan.png
node src/ocr.js examples/test_samples/attack.pdf

# 가드레일 적용 명령 실행
node src/cli.js run -- npm test

# 대시보드
npm run dashboard    # http://127.0.0.1:4040
```

## 데모

```sh
npm run demo:agent-runtime   # 전체 데모
npm run demo:judge           # 감시 표면 통합 검사
npm run demo:image           # 공격 샘플 이미지 생성
npm run demo:os-guard        # OS 레벨 파일/프로세스 감시
```

## 요구사항

- Node.js 20+
- Claude API Key (선택): `export ANTHROPIC_API_KEY="..."`

## 라이선스

MIT
