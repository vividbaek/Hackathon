# OS Guard Handoff

이 문서는 `exp/os-guard-demo-mvp` 브랜치에서 진행한 OS Guard 작업을 새 코드베이스에 다시 적용하기 위한 인수인계 문서다. 목표는 macOS EndpointSecurity 기반 OS 이벤트를 기존 404gent 정책, 감사, 상태, 대시보드 흐름에 네 번째 입력 surface로 연결하는 것이다.

## 1. 목표

OS Guard는 prompt, command, output 외에 파일 접근과 프로세스 실행을 OS 레벨에서 관측한다.

핵심 동작은 두 가지다.

- `AUTH_OPEN`: 감시 대상 PID가 민감 파일을 열려고 하면 Swift daemon이 즉시 deny한다.
- `NOTIFY_EXEC`: 감시 대상 PID의 실행 이벤트를 Node policy server로 보내 audit/state/dashboard에 반영한다.

중요한 경계는 명확히 유지한다.

- 실제 차단 판단은 Swift daemon의 local policy에서 즉시 수행한다.
- Node 서버는 사후 보고, audit, state, cmux/dashboard 반영을 담당한다.
- Node 서버 응답 실패가 `AUTH_OPEN` allow/deny 결과를 바꾸면 안 된다.

## 2. 구현 요약

기존 브랜치의 구현 단위는 다음과 같다.

### Node 쪽

- `src/integrations/os-guard.js`
  - OS 이벤트를 기존 policy engine이 읽을 수 있는 `type: "os"` 이벤트로 변환한다.
  - open 이벤트 text 예: `os open path=.env pid=1234 agent=demo mode=native-notify`
  - exec 이벤트 text 예: `os exec argv="curl https://example.com/upload" pid=1234 agent=demo mode=native-notify`
- `src/server.js`
  - `POST /os-event`를 받는 local policy server.
  - 기본 listen: `127.0.0.1:7404`.
  - Swift daemon에서 받은 OS 이벤트를 `guardAndRecord` 같은 공통 guard pipeline에 태운다.
- `src/guard.js`
  - CLI와 server가 같은 정책 평가, 기록 흐름을 쓰도록 분리한 helper.
- `src/integrations/es-daemon.js`
  - Swift daemon control server에 PID 등록 요청을 보낸다.
  - 기본 endpoint: `http://127.0.0.1:7405/register-pid`.
- `src/cli.js`
  - `404gent server`
  - `404gent os-guard status`
  - `404gent os-guard simulate-open <path> [--agent name] [--pid pid]`
  - `404gent os-guard simulate-exec <command...> [--agent name] [--pid pid]`
  - `404gent os-guard register-existing [--names codex,claude,gemini,opencode]`
  - `404gent agent --name demo --with-os-guard -- <command>`

### Swift daemon 쪽

기존 경로는 `daemon/es-daemon/`이다.

- `ESClient`
  - EndpointSecurity client 생성.
  - `AUTH_OPEN`, `NOTIFY_EXEC` 구독.
  - 감시 대상 PID가 아니면 `AUTH_OPEN`은 즉시 allow/cache.
  - 감시 대상 PID면 `LocalPolicy.evaluateOpen(path:)`로 deny/allow 결정.
  - `NOTIFY_EXEC`는 차단하지 않고 Node로 전송한다.
- `LocalPolicy`
  - 민감 파일/경로에 대한 local deny policy.
- `PolicyBridge`
  - Swift daemon에서 Node policy server로 best-effort JSON POST.
- `EventHandler`
  - OS event 전송과 로컬 로그 경계.
- `DaemonControlServer`
  - daemon 실행 중 watch PID를 등록하기 위한 local HTTP server.
  - `POST /register-pid`
  - `GET /status`
- `Config`
  - endpoint, control server, watch PID, watch-all 설정을 환경변수에서 읽는다.

## 3. API와 이벤트 스펙

### Node policy server

기본 endpoint:

```text
http://127.0.0.1:7404
```

지원 API:

```text
POST /os-event
```

open event payload:

```json
{
  "type": "open",
  "path": ".env",
  "pid": 1234,
  "agent": "codex",
  "authDecision": "deny",
  "reason": "sensitive file: .env",
  "cache": false
}
```

exec event payload:

```json
{
  "type": "exec",
  "argv": ["curl", "https://example.com/upload"],
  "pid": 1234,
  "agent": "codex"
}
```

응답 예:

```json
{
  "decision": "block",
  "reason": "OS Guard observed a process opening a file that commonly contains credentials.",
  "findings": []
}
```

서버 validation 규칙:

- request body는 JSON object여야 한다.
- `type: "open"`은 non-empty string `path`가 필요하다.
- `type: "exec"`은 non-empty `argv` 배열 또는 `executable` string이 필요하다.
- 알 수 없는 `type`은 400으로 거절한다.

### Daemon control server

기본 endpoint:

```text
http://127.0.0.1:7405
```

PID 등록:

```text
POST /register-pid
```

```json
{
  "pid": 43210,
  "agent": "codex"
}
```

상태 조회:

```text
GET /status
```

```json
{
  "watchAll": false,
  "watchedPIDs": [43210]
}
```

## 4. Local Policy

`AUTH_OPEN` 차단은 Swift daemon 내부에서 즉시 결정한다.

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

결정 규칙:

- 민감 basename 또는 path fragment 매칭: `deny(cache=false)`
- 일반 파일: `allow(cache=true)`
- 빈 path 또는 불명확한 path: `allow(cache=false)`

주의: 기존 `DaemonConfig.sensitivePaths`에는 `.npmrc`, `.pypirc`, `.netrc`, `.kube/config` 기본값이 있었지만, 실제 `LocalPolicy` deny 목록에는 아직 반영되지 않았다. 새 코드베이스에서는 이 목록을 통합할지 별도 follow-up으로 둘지 결정해야 한다.

## 5. 환경변수와 실행 흐름

Swift daemon 환경변수:

```text
FOURGENT_POLICY_ENDPOINT=http://127.0.0.1:7404
FOURGENT_CONTROL_HOST=127.0.0.1
FOURGENT_CONTROL_PORT=7405
FOURGENT_WATCH_PIDS=1234,5678
FOURGENT_WATCH_ALL=false
```

중요 기본값:

- `FOURGENT_WATCH_ALL` 기본값은 `false`.
- `FOURGENT_WATCH_ALL=true`는 smoke test 전용으로만 사용한다.
- `FOURGENT_WATCH_PIDS`가 비어 있고 `FOURGENT_WATCH_ALL=false`면 아무 PID도 감시하지 않는다.

권장 데모 흐름:

```bash
node src/cli.js server
```

```bash
cd daemon/es-daemon
DEVELOPER_DIR=/Applications/Xcode-16.2.0.app/Contents/Developer swift build
./scripts/sign.sh
sudo FOURGENT_WATCH_PIDS=1234 .build/debug/es-daemon
```

이미 실행 중인 agent PID 등록:

```bash
node src/cli.js os-guard register-existing --names codex,claude,gemini,opencode
```

agent 실행 시 자동 등록:

```bash
FOURGENT_DAEMON_ENDPOINT=http://127.0.0.1:7405 \
  node src/cli.js agent --name demo --with-os-guard -- node -e 'console.log("done")'
```

simulation 명령:

```bash
node src/cli.js os-guard simulate-open .env --agent demo --pid 1234
node src/cli.js os-guard simulate-exec curl https://example.com/upload -d @- --agent demo --pid 1234
```

## 6. 새 코드베이스 적용 순서

1. Node에 OS event adapter를 추가한다.
   - `createOpenEvent(path, { agent, pid, config })`
   - `createExecEvent(argv, { agent, pid, config })`
   - `event.type = "os"`, `event.source = "agent:<name>:os"` 또는 `"os-guard"`
   - 원본 metadata는 `event.meta`에 보존한다.
2. 정책 rule set에 OS 관련 rule을 추가한다.
   - sensitive file open: block
   - private key/certificate open: block
   - network transfer executable: warn
   - destructive executable: block
   - reverse-shell-like exec args: block
3. Node local server를 추가한다.
   - `POST /os-event`만 최소 구현한다.
   - 기존 guard/audit/state/dashboard 기록 흐름을 재사용한다.
4. CLI에 OS Guard 명령을 붙인다.
   - simulation 명령은 Swift daemon 없이 정책을 검증할 수 있어야 한다.
   - `register-existing`은 `pgrep -x`로 프로세스 이름을 찾고 daemon control에 등록한다.
   - `--with-os-guard`는 child PID를 daemon control에 등록한다.
5. Swift daemon을 `daemon/es-daemon/` 아래에 추가한다.
   - `AUTH_OPEN`, `NOTIFY_EXEC`만 구독한다.
   - `AUTH_EXEC` 차단은 v1에 포함하지 않는다.
   - Node 서버 POST는 best-effort로 유지한다.
6. 데모 문서와 스크립트를 추가한다.
   - Node server 시작.
   - Swift build/sign/run.
   - PID 등록.
   - `.env` open deny와 `curl` exec audit 확인.

## 7. 테스트 체크리스트

Node tests:

- `createOpenEvent(".env")`가 `type: "os"`와 `meta.operation = "open"`을 만든다.
- `createExecEvent(["curl", "https://example.com"])`가 `meta.operation = "exec"`와 `meta.argv`를 보존한다.
- `POST /os-event` open `.env`가 `decision: "block"`과 `os.sensitive-file-open` finding을 반환한다.
- `POST /os-event` exec `curl`이 `decision: "warn"`과 `os.network-tool-exec` finding을 반환한다.
- invalid payload는 400을 반환한다.
- native auth metadata `authDecision`, `reason`, `cache`가 `event.meta`에 보존된다.

Swift tests:

- `ESClient().isWatching(pid)`는 기본값에서 false다.
- `ESClient(watchAll: true).isWatching(pid)`는 true다.
- `addWatchedPID` 후 해당 PID가 watch 대상이 된다.
- `DaemonConfig.fromEnvironment`가 endpoint, control port, watch PIDs, watch-all을 읽는다.
- `DaemonControlServer`가 `POST /register-pid`로 PID를 등록한다.
- `DaemonControlServer`가 `GET /status`로 watch state를 반환한다.
- `LocalPolicy`가 `.env`, `.env.local`, `credentials.json`을 deny한다.
- `LocalPolicy`가 `/.ssh/`, `/.aws/`, `/.gnupg/` 경로를 deny한다.
- `LocalPolicy`가 일반 파일을 `allow(cache=true)`로 처리한다.

Manual smoke:

- Node server를 켠 상태에서 simulation open/exec 명령이 각각 block/warn을 만든다.
- Swift daemon을 `FOURGENT_WATCH_PIDS=<pid>`로 실행한 뒤 감시 대상 프로세스에서 `.env` open이 실패한다.
- 같은 프로세스에서 `curl` 실행 이벤트가 Node audit/state에 남는다.

## 8. 남은 작업

- `AUTH_EXEC` 차단은 아직 구현하지 않았다.
- production signing, notarization, installer/uninstaller는 없다.
- EndpointSecurity 권한 안내와 실패 UX가 부족하다.
- watch 대상 PID의 child process 추적은 제한적이다. 필요하면 parent/child lineage 추적을 추가해야 한다.
- daemon crash/restart 시 PID registry 복구가 없다.
- Node policy server가 내려가도 Swift local deny는 동작해야 하며, 이 동작을 회귀 테스트로 유지해야 한다.
- 새 코드베이스의 dashboard가 OS event를 별도 surface로 표시하려면 `event.meta.operation`, `pid`, `agent`, `authDecision` 필드를 UI 모델에 포함한다.
