# OS Guard 작업 정리

이 문서는 `exp/os-guard-demo-mvp` 브랜치에서 진행한 OS Guard 관련 작업을 한 번에 보기 위한 작업 기록이다.

## 1. 목표 변화

초기 목표는 발표 가능한 simulated OS Guard MVP였다. 이후 범위가 확장되면서 다음 순서로 발전했다.

1. Simulated OS Guard
   - 실제 macOS EndpointSecurity 없이 OS 이벤트처럼 보이는 데이터를 생성.
   - 기존 policy/audit/state/cmux 흐름에 `type: "os"` 이벤트를 태움.
2. Swift EndpointSecurity skeleton
   - 실제 ES 차단 전, 빌드 가능한 Swift daemon 구조를 만듦.
   - `ESClient`, `EventHandler`, `PolicyBridge`, `Config` 경계를 분리.
3. ES NOTIFY + Node policy server
   - Swift daemon이 실제 ES `NOTIFY_OPEN`, `NOTIFY_EXEC`를 관측.
   - 관측 이벤트를 Node `POST /os-event`로 전달.
   - Node가 기존 policy/audit/state/cmux pipeline을 재사용.
4. AUTH_OPEN 차단
   - `AUTH_OPEN`으로 민감 파일 open을 실제 deny.
   - `NOTIFY_EXEC`는 실행 감사/로그 용도로 유지.
   - AUTH 판단은 Node가 아니라 Swift `LocalPolicy`에서 즉시 수행.

## 2. 현재 아키텍처

```text
Agent / Process
  |
  | open(".env")
  v
macOS EndpointSecurity
  |
  | AUTH_OPEN
  v
Swift es-daemon
  |
  | LocalPolicy evaluates path immediately
  | - sensitive file/path: DENY
  | - ordinary file: ALLOW
  v
es_respond_auth_result(...)
  |
  | best-effort async POST
  v
404gent Node policy server
  |
  | POST /os-event
  v
shared guard pipeline
  |
  v
audit / state / cmux
```

`NOTIFY_EXEC`는 별도 차단 없이 실행 감시 이벤트로만 동작한다.

```text
Agent / Process
  |
  | exec("curl")
  v
macOS EndpointSecurity NOTIFY_EXEC
  |
  v
Swift es-daemon
  |
  | best-effort async POST
  v
404gent Node policy server
  |
  v
audit / state / cmux
```

## 3. Node 쪽 변경

### 공통 guard pipeline

추가 파일:

- `src/guard.js`

역할:

- `guard(event, config)`
- `recordReport(report, config)`
- `guardAndRecord(event, config)`

CLI와 HTTP server가 같은 정책 평가/기록 흐름을 쓰도록 분리했다.

### Policy server

추가 파일:

- `src/server.js`

추가 명령:

```bash
node src/cli.js server
```

기본 endpoint:

```text
http://127.0.0.1:7404
```

지원 API:

```text
POST /os-event
```

open event 예시:

```json
{
  "type": "open",
  "path": ".env",
  "pid": 1234,
  "agent": "demo",
  "authDecision": "deny",
  "reason": "sensitive file: .env",
  "cache": false
}
```

exec event 예시:

```json
{
  "type": "exec",
  "argv": ["curl", "https://example.com/upload"],
  "pid": 1234
}
```

응답 예시:

```json
{
  "decision": "block",
  "reason": "OS Guard observed a process opening a file that commonly contains credentials.",
  "findings": []
}
```

Node 서버는 Swift의 AUTH 판단을 대신하지 않는다. Node는 보고/audit/cmux 업데이트를 담당한다.

## 4. Swift daemon 변경

주요 경로:

- `daemon/es-daemon/Sources/ESDaemonCore/ESClient.swift`
- `daemon/es-daemon/Sources/ESDaemonCore/EventHandler.swift`
- `daemon/es-daemon/Sources/ESDaemonCore/PolicyBridge.swift`
- `daemon/es-daemon/Sources/ESDaemonCore/Config.swift`
- `daemon/es-daemon/Sources/ESDaemonCore/LocalPolicy.swift`

### ESClient

현재 구독 이벤트:

```text
AUTH_OPEN
NOTIFY_EXEC
```

동작:

- `AUTH_OPEN`
  - PID 감시 대상 여부 확인.
  - 감시 대상이 아니면 즉시 `ALLOW cache=true`.
  - 감시 대상이면 `LocalPolicy.evaluateOpen(path:)`로 판단.
  - 모든 AUTH 분기에서 `es_respond_auth_result`를 호출.
  - 응답 후 Node로 비동기 전송.
- `NOTIFY_EXEC`
  - 감시 대상이면 Node로 비동기 전송.
  - 실행 차단은 하지 않음.

### LocalPolicy

추가 파일:

- `daemon/es-daemon/Sources/ESDaemonCore/LocalPolicy.swift`

deny basename:

```text
.env
.env.local
.env.production
.env.development
credentials.json
secrets.json
```

deny path fragments:

```text
/.ssh/
/.aws/
/.gnupg/
```

결정:

```text
sensitive path/file -> deny(cache=false)
ordinary file       -> allow(cache=true)
empty/unclear path  -> allow(cache=false)
```

### Config

환경변수:

```text
FOURGENT_POLICY_ENDPOINT=http://127.0.0.1:7404
FOURGENT_DAEMON_ENDPOINT=http://127.0.0.1:7405
FOURGENT_WATCH_PIDS=1234,5678
FOURGENT_WATCH_ALL=true
```

중요한 기본값:

- `FOURGENT_WATCH_ALL` 기본값은 `false`.
- `FOURGENT_WATCH_ALL=true`는 테스트 전용.
- `FOURGENT_WATCH_PIDS`가 비어 있고 `FOURGENT_WATCH_ALL=false`면 아무 PID도 감시하지 않는다.

### PolicyBridge

Swift daemon에서 Node policy server로 best-effort POST를 보낸다.

실패 시:

- AUTH allow/deny 결과에 영향 없음.
- Swift 쪽에서는 `PolicyDecision(decision: "error", reason: ...)`로 로컬 로그만 남긴다.

### Daemon control

Swift daemon은 PID 등록을 위해 별도 control server를 연다.

```text
http://127.0.0.1:7405
```

지원 API:

```text
POST /register-pid
GET /status
```

예시:

```json
{
  "pid": 43210,
  "agent": "codex"
}
```

역할:

- `404gent agent --with-os-guard -- ...`가 spawn한 child PID를 런타임에 등록.
- `404gent os-guard register-existing --names ...`가 이미 실행 중인 agent PID를 등록.
- `FOURGENT_WATCH_PIDS` 수동 방식과 병행 가능.

## 5. Entitlement / Signing

추가 파일:

- `daemon/es-daemon/es-daemon.entitlements`
- `daemon/es-daemon/scripts/sign.sh`

서명:

```bash
cd daemon/es-daemon
DEVELOPER_DIR=/Applications/Xcode-16.2.0.app/Contents/Developer swift build
./scripts/sign.sh
```

`sign.sh`는 ad-hoc signing을 사용한다.

```bash
codesign --sign - \
  --entitlements es-daemon.entitlements \
  --force \
  .build/debug/es-daemon
```

## 6. 실행 흐름

### 서버 실행

repo root에서:

```bash
node src/cli.js server
```

### daemon 실행

특정 PID만 감시:

```bash
cd daemon/es-daemon
sudo FOURGENT_WATCH_PIDS=1234 .build/debug/es-daemon
```

테스트 전용 전체 감시:

```bash
cd daemon/es-daemon
sudo FOURGENT_WATCH_ALL=true .build/debug/es-daemon
```

`FOURGENT_WATCH_ALL=true`는 `AUTH_OPEN`이 시스템 전체 파일 open 경로에 걸리기 때문에 운영/데모 기본값으로 쓰지 않는다.

런타임 PID 등록:

```bash
node src/cli.js agent --name demo --with-os-guard -- codex
node src/cli.js os-guard register-existing --names codex,claude,gemini,opencode
```

## 7. 테스트 및 검증

현재 통과한 검증:

```bash
npm test
```

결과:

```text
43/43 pass
```

Swift:

```bash
DEVELOPER_DIR=/Applications/Xcode-16.2.0.app/Contents/Developer swift test
```

결과:

```text
9/9 pass
```

Whitespace:

```bash
git diff --check
```

결과:

```text
pass
```

Signing:

```bash
cd daemon/es-daemon
./scripts/sign.sh
```

결과:

```text
.build/debug/es-daemon: replacing existing signature
```

## 8. 관련 커밋

OS Guard 관련 커밋:

```text
a798758 feat: add simulated os guard demo
b1b3c00 feat: add endpoint security daemon skeleton
fdf8a05 docs: document es daemon xcode build path
2ec8133 feat: ES NOTIFY 이벤트를 정책 서버에 연결
```

현재 AUTH_OPEN 작업은 위 커밋 이후의 미커밋 변경분이다.

## 9. 현재 완료 범위

완료:

- OS event type과 OS 전용 rule 추가.
- simulated open/exec CLI 추가.
- `agent --with-os-guard` 상태 표시.
- Swift ES daemon skeleton.
- Node local policy server.
- Swift ES `NOTIFY_OPEN`, `NOTIFY_EXEC` 관측.
- Swift to Node `/os-event` HTTP bridge.
- `AUTH_OPEN` 민감 파일 로컬 차단.
- `NOTIFY_EXEC` 감사 이벤트 유지.
- Swift daemon control server `7405`.
- `agent --with-os-guard` child PID 자동 등록.
- 이미 실행 중인 agent PID 등록 명령.
- ad-hoc entitlement/sign script.
- Node/Swift 테스트와 문서 업데이트.

제외/후속:

- `AUTH_EXEC` 차단.
- `AUTH_UNLINK` 차단.
- 네트워크 정책을 OS 레벨에서 차단.
- production Developer ID signing.
- launchd 배포.
- uninstall/install packaging.

## 10. 데모 포인트

발표에서 강조할 수 있는 메시지:

```text
404gent는 prompt/command/output guard에 더해 OS-level guard까지 확장됐다.
민감 파일 open은 Swift EndpointSecurity AUTH_OPEN에서 즉시 차단하고,
실행 이벤트는 NOTIFY_EXEC로 감시해 audit/state/cmux에 연결한다.
```

핵심 차별점:

- Node 왕복 없이 Swift에서 즉시 차단.
- Node 서버는 audit/cmux/reporting에 집중.
- 기존 policy/audit/state/cmux pipeline 재사용.
- simulated demo와 native daemon이 같은 OS Guard event model을 공유.
