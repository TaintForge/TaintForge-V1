# TaintForge 워크플로우 정리

AI 에이전트(Codex) 기반 화이트박스 보안 분석 파이프라인의 전체 흐름을 정리함. 핵심 원칙은 **에이전트가 취약점을 찾고, 툴은 단서·교차검증만 제공함**. 모든 취약점(finding)은 에이전트가 직접 작성함.

---

## 0. 한눈에 보는 전체 흐름

```
타깃 코드 (targets/<app>)
   │
   ▼
[SEED] 툴로 코드 모델 생성 (call graph + 모듈 분할)   ← LLM 안 씀, 한 번만, 결정론적
   │
   ├──────────────┬──────────────┐
   ▼              ▼              ▼
[A 생산자]   [B 생산자]   [C 소비자]   [D 익스플로잇]   ← 4개 Codex 세션 병렬
 인젝션          로직/접근제어    수렴(검증·재현)
 sink→역추적     entry→자원      계속 돌면서 소비
   │              │              ▲
   └──────┬───────┘              │
          ▼                      │
   workspace/findings/  ◄────────┘            ← 공유 큐 (파일락)
   (취약점 후보 스트림)
          │
          ▼
   [C가 단계별로 처리]
   교차검증 → 라이브 재현 → 공개여부 검색 → PoC 작성 → 보고서
          │
          ▼
   report.md (랭킹) + report/<id>/{poc.py, finding.md}
```

---

## 1. SEED — 코드 모델 생성 (LLM 안 씀)

분석 시작 전에 **툴이 결정론적으로 코드 지도를 만듦**. 이건 판단이 아니라 사실 추출이므로 LLM을 안 쓰고 한 번만 함. 산출물은 두 개: `workspace/CODE_MODEL.json`(구조 지도)와 `workspace/coverage.json`(공격표면 트리).

### 1-1. AST 파싱 — ast(파이썬)+정규식으로 구조 추출

파이썬은 표준 `ast` 모듈로 진짜 AST를 만들어 정확히 뽑고, 그 외 언어(PHP/JS/TS/Ruby/Go/Java...)는 언어별 정규식 추출기로 함수·클래스·호출을 뽑음. (tree-sitter는 나중에 끼울 수 있게 출력 형태를 맞춰뒀지만 현재 의존성은 없음.)

- **함수·메서드 정의** — 언어마다 노드 타입이 다름. PHP `function_definition`·`method_declaration`, JS `function_declaration`·`method_definition`, Ruby `method`·`singleton_method` 등. 각 정의에서 이름·시작줄을 뽑아 "이 파일에 어떤 함수가 있다"를 기록.
- **호출(call)** — `foo()`, `obj.bar()`, `Klass.baz` 모두 호출 노드. 호출자(어느 함수 안에서)와 피호출자(무슨 이름) 쌍을 뽑음.
- 파이썬 `ast` 파싱이 실패하면(문법 오류 등) 정규식 추출기로 떨어져서 0이 되진 않게 함.

**왜 AST냐**: 정규식은 `function`이라는 단어는 잡아도 "이게 정의인지, 문자열 안인지, 주석인지"를 구분 못 함. AST는 문법적으로 정확해서 — 주석·문자열·중첩을 헷갈리지 않고 진짜 정의/호출만 뽑음. 콜그래프 정확도가 여기서 갈림.

### 1-2. 콜그래프 — `누가 무엇을 호출하는가`

추출한 (호출자→피호출자) 쌍을 모아 **콜그래프(call_graph)**를 만듦. 피호출자 이름을 정의 위치(어느 파일의 어느 함수)로 해소(resolve)해서 파일·함수를 잇는 엣지로 만듦. 이게 데이터 흐름 추적의 지도임 — A(인젝션)는 이걸 **거꾸로** 타서 sink→source 역추적을 하고, B(접근제어)는 entry→자원으로 따라감.

특별 취급: **위험한 내장 함수 호출은 `<builtin-sink>` 엣지로 따로 표시**함. `query`/`exec`/`system`/`unserialize`/`eval`/`include`/`require`/`file_get_contents`/`curl_exec` 등. `include`·`require`·`eval` 같은 건 괄호 없는 언어 구문이라 일반 호출로 안 잡혀서 별도 규칙으로 sink 엣지를 만듦. → A가 "위험지점이 어디 있나"를 콜그래프 조회 한 번으로 열거 가능.

`callgraph.py`로 이 그래프를 질의함: `--stats`(엣지/sink 수), `--callers <name>`(누가 부르나, 한 홉), `--callees <file>`(이 파일이 뭘 부르나), `--trace <name> -d N`(sink에서 entry까지 역방향 경로 N단계).

### 1-3. entry point 추출 — 공격자가 들어오는 문

콜그래프만으론 "어디가 외부 입력 진입점인가"를 모름. 그래서 **라우트/핸들러 패턴으로 entry point를 따로 뽑음**. 언어·프레임워크별 패턴:
- Python: `@app.route`, `@router.get/post`
- Express/Koa: `app.get("/x")`, `router.post(...)`
- Spring: `@GetMapping`, `@RequestMapping`
- Go: `r.HandleFunc`, `mux.Get`
- **Ruby Grape/Rails (이번에 추가)**: `get`/`post`/`put`/`patch`/`delete` + 경로/심볼, `resource`/`resources`/`namespace`/`route_param`/`segment` 블록, Rails 라우트(`get '/x', to:`), 컨트롤러 액션(`def index/show/create/update/destroy/...`)

→ GitLab처럼 거대한 Ruby/Grape 앱이 자기 API 엔드포인트(예: `POST :resume`, `resource :duo_workflows`, `route_param :workflow_id`)를 entry point로 노출하게 됨. 이게 없으면 공격표면을 못 봐서 트리가 무의미해짐(이번에 Ruby 패턴 넣기 전엔 GitLab entry point가 거의 0이었음).

### 1-4. 커버리지 = 계층 트리 (디렉토리 → 모듈 → entry point)

옛날엔 "코드베이스를 디렉토리 단위 모듈로 쪼개고 다 봤나"만 셌음. 문제는 — 깡통 `vendor/`나 헬퍼 라이브러리나 라우트 빽빽한 API 디렉토리나 **전부 동등한 한 칸**이었고, "다음 볼 거"를 알파벳 순으로 줘서 정작 중요한 API가 뒷전이었음. "100% 커버리지"가 "모든 파일 한 번 훑음"이라 실속을 보장 못 함.

이번에 **공격표면 트리**로 바꿈:
- **모듈 분할** — 디렉토리를 모듈로 쪼개되, 한 모듈이 너무 크면(`TF_SPLIT_THRESHOLD`, 기본 120파일) 자식 디렉토리로 더 쪼갬. 깊이는 `TF_MAX_DEPTH`(기본 4)까지. GitLab처럼 깊고 큰 코드는 `ee/lib/api/ai/duo_workflows` 수준까지 잘게 들어감. (전엔 임계값 400·깊이 2라 `app/services` 하나가 통째 한 모듈 = 수박 겉핥기였음)
- **각 모듈에 entry point 부착** — CODE_MODEL의 entry point를, 그 파일이 속한 모듈에 매달음. 즉 모듈마다 "이 안에 어떤 라우트가 있다"가 붙음. → 커버리지가 *디스크의 파일*이 아니라 *도달 가능한 공격표면*을 반영함.
- **`--next`는 공격표면 우선** — pending 모듈 중 entry point 있는 것(라우트 노출)을 leaf 라이브러리보다 먼저, entry point 많은 순으로 줌. 같은 시간에 위험한 코드부터 보게 됨.
- **`--tree`** — 디렉토리→모듈→entry point 계층을 status(✓/·)와 함께 출력. 각 라우트(`→ POST resume  ...:line`)까지 보여서, A/B가 "이 라우트에서 안쪽으로 추적"을 바로 시작할 수 있음.
- **`--summary`에 공격표면 별도 추적** — "모듈 N/M 분석"뿐 아니라 "entry-point 모듈 N/M 분석"을 따로 보고. "라이브러리 다 봤나"가 아니라 "라우트를 다 봤나"가 진짜 지표.

**효과(이번에 합성 GitLab 구조로 검증함)**: 전엔 `--next`가 깡통 `app/models`를 먼저 줬는데, 이제 entry point 8개 달린 `ee`(API)를 먼저 줌. 우리가 손으로 힘들게 찾았던 그 **`POST :resume`(Duo 명령주입) 엔드포인트가 자동으로 entry point로 인식되어 트리 최상단 우선순위**로 올라옴. 예전 방식이면 그 디렉토리가 "2 files"로 묻혀 한참 뒤에나 봤을 것.

**왜 이렇게 함**: 코드를 통째로 LLM에 던지면 (1) 컨텍스트에 안 들어가고 (2) 멀리 떨어진 source·sink 연결을 놓치고 (3) "다 봤다"는 보장이 없음. 그래서 기계적 구조추출(AST·콜그래프·entry point)은 툴이 한 번에 정확히 하고, LLM은 그 지도 위에서 판단만 함. 그리고 커버리지를 트리로 만들어 — 무한정 넓은 코드에서 **공격자가 실제 도달하는 경로부터** 유한한 우선순위로 훑게 함.

---

## 2. 생산자 A — 인젝션 / 데이터 흐름

SQLi, 명령·코드 인젝션, XSS, SSRF, 경로 순회, 파일 인클루전, 역직렬화 등을 찾음.

- **sink-first(역추적) 방식** — 위험한 연산(sink)에서 시작해서 call graph를 **거꾸로** 따라가며 공격자 입력이 거기 도달하는지 봄.
- 경로상의 sanitizer(이스케이프·검증)를 판단함. sink 자체 파일에선 안전해 보여도, 몇 단계 떨어진 곳에서 오염된 데이터가 들어오는 경우를 잡음.
- OpenGrep(SAST)이 주는 단서는 `workspace/hints/`에 쌓이지만, **단서는 "여기 봐라"일 뿐 취약점이 아님**. 에이전트가 직접 판단해서 작성함.

**왜 sink-first**: 입력(source)은 코드 어디에나 있어서 정방향 추적은 폭발적으로 퍼지고 대부분 헛다리임. 반면 위험한 연산은 **유한하고 열거 가능**함. 모든 취약점은 결국 sink에서 끝나므로, "이 N개의 위험지점에 오염 데이터가 닿는가?"로 문제를 한정된 체크리스트로 바꿈.

---

## 3. 생산자 B — 로직 / 접근제어

SAST가 못 보는 버그를 찾음: IDOR/BOLA, 권한 누락, 권한 상승, 인증·세션 우회, 비즈니스 로직 결함.

- **entry→자원(정방향) 방식** — 라우트(진입점)에서 시작해 자원 접근까지 따라가며, 경로 어딘가에 **인가 게이트**가 있는지 확인함.
- 체인 전체(`핸들러 → 서비스 → 저장소/객체 로드`)를 따라가며 묻음: 인증 체크, 역할/권한 체크, 그리고 **소유권/테넌트 체크**가 있는가?
- 소유권 체크 없이 `findById` 같은 게 라우트에서 도달 가능하면 → IDOR. 상태 변경 액션에 역할 체크가 없으면 → 접근제어 결함.

**왜 별도 트랙**: 인젝션과 정반대 방향이고, 툴이 거의 장님임("소유권 체크 누락"은 grep 패턴이 아님). 앱 이해(라우트, 권한 모델)가 필요해서 A와 다른 방법·다른 시드를 씀. 한 세션이 둘 다 하면 쉬운 인젝션에 치우치고 로직 버그를 소홀히 함.

---

## 4. 소비자 C — 수렴 (검증·재현)

A·B가 생산하는 동안 **계속 돌면서** 큐의 finding을 소비함. finding 하나당 단계별로 증명 강도를 높임.

### 4-1. 교차검증
독립적인 엔진(CodeQL, PHP는 OpenGrep으로 자동 폴백)으로 같은 패턴이 맞는지 확인함. 동의하면 상태를 `cross_validated`로 올림.

### 4-2. 라이브 재현 (`-u URL` 줬을 때)
실제 돌아가는 인스턴스에 요청을 쏴서 진짜 터지는지 봄. 취약점 종류별로 다른 도구를 씀:

- **probe.py** — HTTP 요청 도구. `--jar`로 **세션(쿠키)을 유지**함. 에이전트가 코드에서 로그인 흐름을 직접 파악해 로그인하고, 그 세션으로 보호된 자원에 접근함.
- **IDOR/접근제어** — 계정 두 개를 각자 jar에 로그인시킨 뒤, **한 계정 세션으로 다른 계정의 자원**을 요청함. 남의 데이터가 보이면 확정. (일반 유저 2명 이상 필요)
- **SSRF** — `canary.py`(out-of-band 서버)를 띄워두고, 타깃이 `http://<canary>/<토큰>`을 가져오게 만든 뒤 콜백이 오는지 확인함. 오면 확정.
- **XSS** — 반사만으론 증명 안 됨. `browser_probe.py`(헤드리스 Chromium)로 **실제 JS가 실행되는지** 확인함. dialog가 뜨거나 주입한 마커가 실행되면 `executed:true`. 실행된 것만 재현 인정.

재현 성공이면 `reproduced`, 실패면 `false_positive`, 판정 불가면 `needs_reanalysis`(생산자에게 되돌림).

### 4-3. 공개여부 검색 (재현된 것만)
`reproduced`/`confirmed`된 것만 웹검색으로 "이미 알려진 CVE냐, 새거냐"를 판단함.
- `known` — 공개된 CVE/어드바이저리와 일치 (참조 기록)
- `novel` — 공개 자료 없음 → **잠재 0-day**
- `inconclusive` — 불확실

**왜 재현된 것만**: 증명 안 된 후보에 검색 낭비 안 하려고. 그리고 가장 강한 주장(0-day)에 가장 많은 검증을 붙이려고.

### 4-4. PoC 작성 + 개별 보고서
재현된 취약점마다 에이전트가 그 버그에 맞는 `poc.py`를 작성함(requests 사용). pre-auth면 로그인 없이, 다단계면 필요한 만큼, PASS/FAIL 출력. `emit_poc.py`가 이걸 받아서 취약점별 폴더를 만듦:
```
workspace/report/<id>/poc.py        # 단독 실행 가능, python3 poc.py로 재현
workspace/report/<id>/finding.md    # 그 취약점 하나의 개별 보고서
```
취약점별로 분리 관리함(합치지 않음). `report.md`는 전체 랭킹 인덱스로 남김.

---

## 4.5 익스플로잇 — 에이전트 D (크리티컬 건 무기화)

C가 "진짜다"를 증명하면, **D**는 그걸 **완전히 이해된 익스플로잇으로** 끌어올림. 단 크리티컬 클래스만(RCE, 명령주입, SQLi, 인증우회, 역직렬화, 내부SSRF). 계속 루프:

- **선택** — `reproduced`/`confirmed`이면서 크리티컬 클래스이고 아직 안 판 것만. 나머지(low/medium, 미증명)는 D 일이 아님.
- **심화 (각 단계 실측)** — 증명된 primitive에서 출발해 **최대 임팩트까지 체인**(블라인드 SQLi→불린/타임 추출; 단일토큰 명령주입→경로로 페이로드 파일 실행; SSRF→내부/메타데이터; 인증우회→관리자 액션). **방어 우회** — sanitizer/이스케이프/따옴표가 막으면 *정확히 뭐가 통과하는지* 분석해서 실제로 실행되는 우회를 찾음(말로 때우지 않음).
- **정직하게 기록** — `exploit` 객체에 `{depth, primitive, max_impact, steps, mitigations_bypassed, constraints, working_poc, oob_evidence}`. 임팩트가 제한적이면(예: 인자 없는 단일 명령만 실행) 그 한계를 `constraints`에 그대로 적음. **정확한 "제한적" 결과가 과장된 것보다 가치 있음.**
- **산출** — `report/<id>/exploit.py`(C의 poc.py와 별도). triage가 💥 무기화 섹션에, 대시보드가 💥 카운터에 표시.

**왜 별도 에이전트**: 재현(C)과 무기화(D)는 사고방식·시간예산이 다름. C는 큐 전체를 계속 흘려보내야 하고, D는 소수에 깊이 파고듦. 분리하면 C가 어려운 익스플로잇 하나에 막혀있는 동안 늦게 오는 finding이 쌓이는 걸 막음. D는 가리킨 타깃만 침 — 본인 소유/허가받은 자산 전용.

---

## 5. 상태 머신 (가설 → 증명)

모든 finding은 **가설**로 시작해서 증명 단계를 거침. `status` 필드가 곧 증명 강도임.

```
candidate          한 분석가의 추론 (가장 약함)
   ↓ 교차검증
cross_validated    독립 엔진도 동의
   ↓ 라이브 재현
reproduced         실제로 터뜨림 (PoC 있음)
   ↓ 트리아지
confirmed          재현 + 완전 정리 (가장 강함)

   ✗ false_positive    반증됨 (보고서에서 제외)
   ↺ needs_reanalysis  판정 불가 → 생산자에게 피드백
```

**왜 단계를 둠**: 정적 툴은 과탐(패턴 매치 ≠ 익스플로잇 가능)하고, LLM은 흐름을 환각할 수 있음. 그래서 단계마다 증명 부담을 높이는 깔때기로 둘 다 거름. 재현(실제로 터뜨림)이 가장 결정적인 증거임.

---

## 6. 동기화 — 4개 프로세스가 어떻게 안 부딪히나

네 세션은 별도 OS 프로세스라 공유 메모리가 없음. 조율은 전부 **파일시스템(`workspace/`)**으로 함. DB·브로커 안 쓰는 이유: 인프라 부담 + 세션 죽으면 날아감. 파일은 영속적이고 `ls`로 들여다볼 수 있음.

- **큐 = 디렉터리** — `workspace/findings/`에 finding 하나당 파일 하나. 파일 존재 = 큐에 있음, `status` = 진행 단계.
- **중복 제거 = 내용 기반 ID** — `id = 해시(track|취약점클래스|sink파일|sink라인)`. 같은 버그를 두 번 찾으면 같은 ID → 같은 파일로 합쳐짐(멱등). 그래서 A·B가 겹쳐도 중복 안 됨.
- **동시성 안전 = 파일락** — finding 쓰기 전에 `fcntl` 배타적 락. 세 프로세스가 같은 파일 써도 직렬화돼서 안 깨짐. append-only라 남의 데이터 안 덮음.
- **파생물은 매번 재생성** — `report.md`와 개별 보고서는 `findings/`에서 파생됨. 점진적으로 동기화하다 어긋나는 대신, 대시보드가 매 사이클 통째로 다시 만듦. 진실의 원천은 항상 `findings/`.

---

## 7. 세션 생명주기 — supervisor

`codex exec` 세션은 **유한함**(에이전트가 끝났다고 판단하거나 토큰 한도에 닿으면 종료). 스트리밍 소비자(C)에겐 치명적임 — 빈 큐를 보고 "완료"로 착각하고 죽으면, 늦게 도착하는 finding을 아무도 재현 안 함.

그래서 각 역할을 **셸 supervisor 루프**로 감쌈:
- 세션이 죽으면 5초 뒤 **자동 재시작**(respawn)
- `MAX_HOURS`(기본 12시간) 또는 `workspace/_stop` 파일이 생길 때까지 계속
- 정지: `touch workspace/_stop`을 **먼저** 한 뒤 프로세스 kill (안 그러면 supervisor가 되살림)

---

## 8. 실행 흐름 요약

```
1. SEED      build_code_model + coverage --init          (결정론적, 한 번)
2. SPAWN     audit.sh가 A·B·C를 supervisor로 띄움; -u면 canary.py도
3. PRODUCE   A(sink 역추적)·B(entry→자원)가 finding 스트림 생성   [candidate]
4. CONVERGE  C가 계속 루프:
               교차검증 → 재현(probe/canary/browser_probe)
               → 공개여부 검색 → poc.py 작성 → 보고서 생성
5. FEEDBACK  재현 실패 → needs_reanalysis → 생산자가 다시 봄
6. RESPAWN   세션 죽으면 supervisor가 재시작 (MAX_HOURS / _stop까지)
7. STOP      touch workspace/_stop; kill; pkill
```

### IDOR 확정 예시 (처음부터 끝까지)
1. **B**가 `자원컨트롤러::조회 → 자원::findById(id)`를 따라가다 경로에 소유권 체크가 없음을 발견 → candidate 작성
2. **C**가 교차검증 후 재현: alice·bob을 각자 jar에 로그인 → alice 세션으로 bob의 자원 요청 → 200 + bob 데이터 확인 → `reproduced`
3. **C**가 "<제품> <버전> <엔드포인트> IDOR CVE" 검색 → 없음 → `disclosure=novel`
4. **C**가 requests 기반 `poc.py` 작성 (alice 로그인 → bob 자원 GET → 유출 검증)
5. `emit_poc.py`가 `report/<id>/` 생성, `triage.py`가 **⚠️ 잠재 0-day** 섹션에 올림

---

## 핵심 한 줄 요약

> **결정론적인 것은 툴로 한 번만, 판단은 집중된 에이전트로, 독립 프로세스는 영속적인 파일로만 조율함. 모든 취약점은 가설로 시작해 실제 재현으로 증명함.**