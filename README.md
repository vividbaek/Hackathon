# 404gent

`404gent`는 cmux 안에서 실행되는 AI 코딩 에이전트를 위한 EDR 스타일 런타임 가드레일 CLI입니다. 에이전트가 코드를 읽고, 명령을 만들고, 터미널 출력을 해석하는 과정에서 위험 신호를 빠르게 탐지하고 기록하는 것을 목표로 합니다.

## 감시 표면

1. **Prompt**: 에이전트에게 전달되기 전의 프롬프트를 검사합니다.
2. **Command**: 실행되기 전의 셸 명령을 검사합니다.
3. **Output**: 터미널에 출력되기 전의 stdout/stderr 내용을 검사합니다.

## 핵심 기능

- Node.js 20+ 기반의 dependency-free ESM CLI
- `404gent scan-prompt`, `scan-command`, `scan-output` 명령 제공
- 기본 정책 룰 기반 위험도 판정
- `.404gent/events.jsonl` 감사 로그와 `.404gent/state.json` 상태 파일 저장
- JSON 설정 파일 로더
- cmux 연동을 위한 초기 통합 모듈 스캐폴딩
- 위험 명령을 실제 실행하지 않는 demo script 구조

## 요구사항

- Node.js 20 이상
- npm
- POSIX shell, demo script 실행 시

## 가장 빠른 테스트 명령

```sh
npm test
```

빠른 동작 확인:

```sh
npm run demo
node src/cli.js scan-command "rm -rf /"
node src/cli.js scan-output "AWS_SECRET_ACCESS_KEY=example"
```

## Judge Demo

`npm run demo:judge`는 프롬프트, 명령, 출력 감시 표면을 한 번에 훑는 데모 흐름입니다. 위험 명령은 실행하지 않고 `404gent scan-command`로만 검사합니다.

## Recovery Demo

`npm run demo:recovery`는 상태 파일을 초기화하고, 위험 이벤트를 기록한 뒤, 복구 모듈이 읽을 수 있는 최소 상태를 만드는 흐름입니다. 현재 단계에서는 스캐폴딩 수준의 동작만 제공합니다.

## Agent Demo

`npm run demo:agents`는 에이전트 워크플로우에서 prompt, command, output을 각각 훅으로 전달하는 상황을 흉내 냅니다. 실제 에이전트 실행 대신 CLI scan 명령만 호출합니다.

## cmux Integration

`src/integrations/cmux.js`는 cmux에서 404gent를 호출하기 위한 통합 지점을 담습니다. 현재는 prompt, command, output payload를 CLI 정책 엔진에 전달할 수 있는 최소 어댑터만 제공합니다. 향후 cmux native hook과 세션 단위 상태 모델을 연결할 예정입니다.

## 알려진 한계

- 기본 룰은 휴리스틱 기반이며 오탐과 미탐이 있을 수 있습니다.
- 셸 파싱은 아직 정교한 AST 기반이 아니며 문자열 검사 수준입니다.
- LLM provider는 mock 스캐폴딩만 포함합니다.
- 복구와 진단 모듈은 초기 인터페이스만 제공합니다.
- cmux native integration은 실제 런타임 훅 연결 전 단계입니다.
