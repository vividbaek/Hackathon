### 1. 한눈에 보기

```bash
┌─────────────────────────────────────────────────────────────┐
│                     AI Agent 워크플로우                        │
│                                                             │
│  [입력]      [실행]      [OS]       [출력]      [화면]           │
│    │          │          │           │           │          │
│    ▼          ▼          ▼           ▼           ▼          │
│ ┌──────┐  ┌──────┐  ┌──────┐   ┌──────┐   ┌──────┐          │
│ │  1   │  │  2   │  │  3   │   │  4   │   │  5   │          │
│ │      │  │      │  │      │   │      │   │      │          │
│ │Prompt│  │Shell │  │ ES   │   │Output│   │Screen│          │
│ │Guard │  │Guard │  │Guard │   │Guard │   │Watch │          │
│ └──────┘  └──────┘  └──────┘   └──────┘   └──────┘          │
│                                                             │
│ 인젝션    위험명령   파일/프로세스  비밀마스킹  실시간개입               │  
│  차단       차단     접근차단                    Ctrl+C          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 각 레이어 상세

### 1️⃣ Prompt Guard

| 항목 | 내용 |
| --- | --- |
| **뭐야?** | 에이전트에게 들어가는 입력(프롬프트) 검사 |
| **언제?** | 에이전트 실행 **전** |
| **어디서?** | 애플리케이션 레벨 (Node.js) |

**막을 수 있는 것 ✅**

```bash
프롬프트 인젝션: "ignore previous instructions..."
탈옥 시도: "you are now DAN..."
역할 우회: "pretend you have no restrictions"
한국어 인젝션: "이전 지시는 무시하고..."
숨겨진 명령: HTML 주석, 인코딩
```

**못 막는 것 ❌**

```bash
에이전트가 자체 생성한 악성 코드
이미 실행 중인 세션 (wrapper 없으면)
새로운 패턴의 인젝션
```

---

### 2️⃣ Shell Guard

| 항목 | 내용 |
| --- | --- |
| **뭐야?** | 에이전트가 실행하려는 Shell 명령어 검사 |
| **언제?** | 명령어 실행 **전** |
| **어디서?** | 애플리케이션 레벨 (Node.js) |

**막을 수 있는 것 ✅**

```bash
환경변수 유출: curl -d $API_KEY ...
파일 유출: cat .env | nc ...
리버스 쉘: bash -i >& /dev/tcp/...
파괴적 명령: rm -rf /, DROP TABLE
클라우드 삭제: aws s3 rb --force
정찰: nmap, sqlmap
```

**못 막는 것 ❌**

```bash
Python open('.env') → Shell 안 거침
Node fs.readFile() → Shell 안 거침
requests.post(secret) → Shell 안 거침
subprocess.run(["cat", ".env"]) → 분리된 인자
```

---

### 3️⃣  🌟 ES Guard (EndpointSecurity)

| 항목 | 내용 |
| --- | --- |
| **뭐야?** | OS 커널에서 파일/프로세스 접근 감시 |
| **언제?** | 시스템 콜 발생 시 (실시간) |
| **어디서?** | **OS 레벨** (커널) |
| **구현 상태** | AUTH_OPEN 차단 ✅ / NOTIFY_EXEC 감시 ✅ |

<aside>
💡

**es Daemon을 띄우자**

---

- **es Daemon?**
    - EndpointSecurity를 사용하는 Swift 프로그램
    - OS에게 "이 에이전트 감시해줘" 요청
    - 이벤트 받으면 판단 + 차단 + 보고

<aside>
❗

**EndpointSecurity는 Swift 써야함**

---

EndpointSecurity는 기본적으로 Apple 전용 API라, Swift/Objective-C로만 사용 가능

Node.js 사용 불가

</aside>

- es-daemon 구조
    
    ```bash
    es-daemon/
    ├── main.swift           # 시작점
    ├── ESClient.swift       # ES 연결, 이벤트 수신
    ├── LocalPolicy.swift    # 로컬 판단 (민감 파일 차단)
    ├── EventHandler.swift   # 이벤트 처리
    ├── PolicyBridge.swift   # 404gent 서버로 보고
    └── Config.swift         # 설정 (PID, 서버 주소)
    ```
    
- 동작 흐름
    
    ```bash
    [es-daemon 시작]
         ↓
    "OS야, AUTH_OPEN 이벤트 알려줘"
         ↓
    [에이전트가 .env 열기 시도]
         ↓
    OS → es-daemon: "43210번이 .env 열려고 해"
         ↓
    es-daemon: "43210 감시 대상이네, .env는 민감 파일이네"
         ↓
    es-daemon → OS: "DENY"
         ↓
    OS → 에이전트: "Permission denied"
         ↓
    es-daemon → 404gent 서버: "차단했어요" (비동기)
         ↓
    404gent → cmux notify: "🚨 .env 접근 차단됨"
    ```
    
</aside>

<aside>
💡

**Cmux를 통한 에이전트별 PID 추적**

---

- 왜 필요한가?
    - ES Guard는 "이 PID 감시해줘"라고 OS에 요청하는 구조
    - PID 없으면 → 모든 프로세스 감시 (노이즈)
    - PID 있으면 → 에이전트만 감시 (정확)
    - 특정 에이전트만 감시하므로 시스템 부하 감소
- PID 수집 로직
    - **init작업**: pgrep으로 이미 실행 중인 에이전트 PID 수집
        - 에이전트 프로세스명으로 필터(codex, claude … )
    - **실행 중 추가되는 에이전트들**: es-daemon의 HTTP API로 PID 등록 (굳)
</aside>

<aside>
💡

**404gent와의 연동**

---

- es-daemon만 사용 → OS 이벤트 수신, 즉시 차단
    - audit 로그 관리 어려움
    - cmux 연동 어려움
- Policy Server를 추가하자
    - audit 로그 기록
    - state 업데이트
    - cmux notify
    - 기존 guard 파이프라인 재사용

---

- 동작 흐름
    
    ```bash
    [es-daemon]
         ↓ .env 차단함
         ↓
    POST /os-event
    {
      "type": "open",
      "path": ".env",
      "pid": 43210,
      "decision": "deny",
      "reason": "sensitive file"
    }
         ↓
    [Policy Server] # 얘는 기록용이라 죽어도 됨. 비동기 처리해서 Latency 최소화하자
         ↓
    1. 기존 guard 파이프라인으로 평가
    2. audit.json에 기록
    3. state 업데이트
    4. cmux notify 전송
         ↓
    [cmux 알림]
    🚨 .env 접근 차단됨
    ```
    
</aside>

차단하는 것 ✅ (AUTH_OPEN)

```bash
- Python open('.env') → AUTH_OPEN → 차단
- Node fs.readFile('.env') → AUTH_OPEN → 차단
- 모든 언어/방식의 민감 파일 열기 → 차단
- ~/.ssh/*, ~/.aws/*, ~/.gnupg/* 접근 → 차단
```

**감시하는 것 👁️ (NOTIFY_EXEC)**

```bash
# 단, NOTIFY_EXEC는 실행 사실만 알 수 있고, 인자/데이터 내용은 직접 알 수 없음
# 여기서의 block은 TODO로 넘기거나, 간단하게 ...?
- subprocess.run(["curl"]) → NOTIFY_EXEC → 감시 + 알림
- 악성 바이너리 실행 → NOTIFY_EXEC → 감시 + 알림
- 자식 프로세스 스폰 → NOTIFY_EXEC → 감시 + 알림
```

**못 막는 것 ❌**

```bash
HTTP body 내용 (연결만 알음)
인코딩된 데이터 전송
네트워크 전송 내용 자체
```

**핵심 포인트**

```bash
Shell Guard가 놓친 것을 ES Guard가 잡음
→ 모든 프로그램은 OS를 거쳐야 하니까
→ 우회 난이도 높음
```

---

### 4️⃣ Output Guard

| 항목 | 내용 |
| --- | --- |
| **뭐야?** | 에이전트 출력에서 민감 정보 탐지/마스킹 |
| **언제?** | 터미널 출력 **전** |
| **어디서?** | 애플리케이션 레벨 (Node.js) |

**막을 수 있는 것 ✅**

```bash
API 키 노출: sk-proj-..., AKIA...
비밀번호: password=...
개인정보 (PII): 이메일, 전화번호
토큰: JWT, OAuth tokens
→ [REDACTED]로 마스킹
```

**못 막는 것 ❌**

```bash
인코딩된 비밀 (base64 등)
커스텀 포맷 (패턴에 없으면)
이미 네트워크로 전송된 데이터
```

---

### 5️⃣ Screen Watch (cmux 실시간 감시)

| 항목 | 내용 |
| --- | --- |
| **뭐야?** | cmux 터미널 화면을 실시간으로 읽고 위험 감지 시 개입 |
| **언제?** | 에이전트 실행 **중** (실시간) |
| **어디서?** | cmux 연동 (read-screen + send-key) |

<aside>
💡

**Cmux의 API를 활용해보자…**

---

단순 알림이 아니라 "실시간 개입" 기능

- `read-screen`
    - cmux 터미널 화면 내용 읽기
- `send-key`
    - cmux surface에 키 입력을 보내는 것
    - (Ctrl+C) 전송으로 프로세스 중단
- `cmux-watch`
    - 실시간 화면 감시 + 자동 개입

---

단순 모니터링을 넘어서, 화면에 민감정보가 출력될 경우 감지하여 즉시 중단

</aside>

**막을 수 있는 것 ✅**

```bash
실행 중 비밀 출력 감지 → 즉시 Ctrl+C
Output Guard가 놓친 것 (이미 출력됐어도)
장시간 실행되는 스크립트 중간에 위험 감지
예상 못한 출력 패턴
```

**못 막는 것 ❌**

```bash
이미 네트워크로 전송된 데이터 (되돌리기 불가)
화면에 안 나타나는 동작
Ctrl+C로 안 멈추는 프로세스
```

**핵심 포인트**

```bash
다른 Guard들이 "실행 전" 차단이라면,
Screen Watch는 "실행 중" 개입
→ 실시간 안전망
```

---

### 레이어별 타이밍

```bash
시간 흐름 →

[입력]     [명령생성]     [실행]      [출력]
   │           │            │           │
   ▼           ▼            │           ▼
┌──────┐   ┌──────┐         │       ┌──────┐
│Prompt│   │Shell │         │       │Output│
│Guard │   │Guard │         │       │Guard │
└──────┘   └──────┘         │       └──────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
         ┌──────┐                    ┌──────┐
         │  ES  │ (OS 레벨)           │Screen│ (실시간)
         │Guard │                    │Watch │
         └──────┘                    └──────┘

      "파일 열 때 차단"           "화면에 뜰 때 개입"
      "실행 시 감시"
```

---

### 커버리지 매트릭스

| 공격 벡터 | Prompt | Shell | ES | Output | Screen |
| --- | --- | --- | --- | --- | --- |
| 프롬프트 인젝션 | ✅ | - | - | - | - |
| 탈옥 시도 | ✅ | - | - | - | - |
| `cat .env | curl` | - | ✅ | ✅ | - | ✅ |
| 리버스 쉘 | - | ✅ | 👁️ | - | - |
| `rm -rf /` | - | ✅ | 👁️ | - | - |
| Python `open('.env')` | - | ❌ | ✅ | ⚠️ | ✅ |
| `subprocess.run(["curl"])` | - | ❌ | 👁️ | - | ⚠️ |
| `requests.post(secret)` | - | ❌ | 👁️ | - | ⚠️ |
| API 키 출력 | - | - | - | ✅ | ✅ |
| 실행 중 비밀 노출 | - | - | - | ⚠️ | ✅ |

```bash
✅ = 차단
👁️ = 감시 (탐지 + 알림, 차단 아님)
⚠️ = 부분적
❌ = 못 잡음
-  = 해당 없음
```

---

### 각 레이어의 특성

| 레이어 | 레벨 | 타이밍 | 동작 | 우회 난이도 |
| --- | --- | --- | --- | --- |
| Prompt Guard | 애플리케이션 | 실행 전 | 차단 | 🟡 중간 |
| Shell Guard | 애플리케이션 | 실행 전 | 차단 | 🟡 중간 |
| **ES Guard (open)** | **OS (커널)** | **실시간** | **차단** | 🟢 **어려움** |
| **ES Guard (exec)** | **OS (커널)** | **실시간** | **감시** | 🟢 **어려움** |
| Output Guard | 애플리케이션 | 출력 전 | 마스킹 | 🟡 중간 |
| Screen Watch | cmux 연동 | 실행 중 | 개입 | 🟡 중간 |

---

### 방어 깊이 (Defense in Depth)

```bash
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   공격이 성공하려면 5개 레이어를 다 뚫어야 함                         │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │ Layer 1: Prompt Guard                               │  │
│   │   ┌─────────────────────────────────────────────┐   │  │
│   │   │ Layer 2: Shell Guard                        │   │  │
│   │   │   ┌─────────────────────────────────────┐   │   │  │
│   │   │   │ Layer 3: ES Guard (OS)              │   │   │  │
│   │   │   │   ┌─────────────────────────────┐   │   │   │  │
│   │   │   │   │ Layer 4: Output Guard       │   │   │   │  │
│   │   │   │   │   ┌─────────────────────┐   │   │   │   │  │
│   │   │   │   │   │ Layer 5: Screen     │   │   │   │   │  │
│   │   │   │   │   │         Watch       │   │   │   │   │  │
│   │   │   │   │   │                     │   │   │   │   │  │
│   │   │   │   │   │    [데이터 보호됨]     │   │   │   │   │  │
│   │   │   │   │   └─────────────────────┘   │   │   │   │  │
│   │   │   │   └─────────────────────────────┘   │   │   │  │
│   │   │   └─────────────────────────────────────┘   │   │  │
│   │   └─────────────────────────────────────────────┘   │  │
│   └─────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 한 줄 요약

| 레이어 | 한 줄 요약 |
| --- | --- |
| **Prompt Guard** | "뭘 시키는지" 검사 |
| **Shell Guard** | "뭘 실행하는지" 검사 |
| **ES Guard (open)** | "뭘 열려고 하는지" 검사 + **차단** |
| **ES Guard (exec)** | "뭘 실행하는지" 검사 + **감시** |
| **Output Guard** | "뭘 내보내는지" 검사 |
| **Screen Watch** | "화면에 뭐 뜨는지" 실시간 감시 + 개입 |