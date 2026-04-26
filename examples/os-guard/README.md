# OS Guard Simulation Demo

이 fixture는 Apple EndpointSecurity entitlement가 없는 환경에서도 OS Guard의 정책 모델을 발표할 수 있게 만든다.

시뮬레이션은 실제 커널 차단이 아니다. 대신 native daemon이 보낼 `open` / `exec` OS 이벤트와 같은 shape을 만들어 기존 policy, audit, vector, state, dashboard 흐름에 기록한다.

실행:

```sh
npm run demo:os-guard
```

기대 흐름:

- `README.md` open은 allow
- `.env` open은 `os-sensitive-file-open`으로 block
- private key open은 `os-private-key-open`으로 block
- `curl` exec은 `os-network-tool-exec`으로 warn
- `rm -rf /` exec은 `os-destructive-exec`으로 block
- Python 우회 예시는 native EndpointSecurity에서 같은 `AUTH_OPEN`으로 잡힌다는 설명과 함께 simulated open event로 기록
- `aws_credentials` open은 `os-cloud-credentials-open`으로 block
- `exfil-agent`가 `.env` open 후 외부 `curl` 전송을 시도하는 연속 사건을 audit/dashboard에 기록

native EndpointSecurity 검증은 `docs/OS_GUARD_TODO.md`의 signing/entitlement TODO가 해결된 뒤 진행한다.
