# TaintForge 워크플로우 정리

AI 에이전트가 웹 소스 코드를 화이트박스로 감사하는 파이프라인. 그 전체 흐름을 정리함.
**취약점은 에이전트가 찾고 툴은 단서·교차검증만 댐.** 모든 취약점(finding)은 에이전트가 직접
작성함. A·B·C·D·E 다섯 역할이 각자 독립 세션으로 동시에 돌면서 `workspace/findings/` 큐 하나를
공유함. 모델 백엔드는 `TF_BACKEND=claude` 또는 `TF_BACKEND=codex`로 고름.

---

## 0. 한눈에 보는 전체 흐름

```
타깃 코드 (targets/<app>)
   │
   ▼
[SEED] seed.sh - 콜그래프 + 모듈별 코드 모델 + 커버리지 트리 + 가설  ← LLM 안 씀, 결정론적
   │
   ├──────────┬──────────┬──────────┬──────────┐
   ▼          ▼          ▼          ▼          ▼
[A 생산자]  [B 생산자]  [C 소비자]   [D 익스플로잇]  [E 재분석]  ← 독립 세션 5개
 인젝션/흐름  로직/접근제어 수렴(검증·재현)  크리티컬 무기화  needs_reanalysis 전담
 sink→역추적  entry→자원   계속 돌며 소비   (C가 확정한 것만)  막힌 건 되살림
   │          │             ▲          ▲             │
   └────┬─────┘             │          │             │
        ▼                   │          │ confirmed   │
 workspace/findings/ ◄──────┴──────────┴─────────────┘
 (취약점 후보 스트림)         │
        │       [A/B가 파서·역직렬화 깊이 팔 때] → leads.json
        │        (lead·primitive 누적, 체인 후보) → C/D가 체인 실현
        ▼
 [C가 단계별로 처리]
 교차검증 → 라이브 재현 → 공식/벤더 제품경계 검토 → 증거 계약 → 공개 이력 → PoC → 보고서
        │
        ▼
 report.md (랭킹) + report/<id>/{poc.py, finding.md, exploit.py}
```

---

## 1. SEED — 코드 모델 생성 (LLM 안 씀)

분석을 시작하기 전에 **툴이 결정론적으로 코드 지도를 만듦**. 판단이 아니라 사실 추출이라 LLM을
안 쓰고 체크아웃당 한 번만 돌림. 진입점은 `seed.sh`임.

```bash
./seed.sh targets/<app> [modules-file]
```

산출물은 넷. `workspace/CODE_MODEL.json`(구조 지도), `workspace/coverage.json`(공격표면 트리),
`workspace/proof_ledger.json`(route·sink 유닛 원장), `workspace/HYPOTHESES.json`(비즈니스 로직
가설). 모듈 파일을 같이 주면 `workspace/cm/<name>.json`에 모듈별 풀 모델이 추가로 깔림.

### 1-1. 심볼·호출 추출 — ast + tree-sitter(+정규식 폴백)

파이썬은 표준 `ast` 모듈로 진짜 AST를 만들어 정확히 뽑음. 그 외 언어(PHP/JS/TS/Ruby/Go/Java...)는
`ts_extract.py`가 tree-sitter 파스 트리로 함수·클래스·호출을 뽑음. tree-sitter가 없거나
`TF_NO_TREESITTER=1`이면 언어별 정규식 추출기로 떨어짐. `build_code_model.sh`는 tree-sitter
백엔드를 실제로 로드할 수 있는 인터프리터를 먼저 골라서 씀(`TF_PY`로 지정 가능). 파이썬 파싱이
문법 오류로 실패해도 정규식 추출기가 받아내서 0이 되진 않음.

- **함수·메서드 정의** — 언어마다 노드 타입이 다름. PHP `function_definition`·`method_declaration`,
  JS `function_declaration`·`method_definition`, Ruby `method`·`singleton_method` 등. 각 정의에서
  이름·시작줄을 뽑아 "이 파일에 어떤 함수가 있다"를 기록.
- **호출(call)** — `foo()`, `obj.bar()`, `Klass.baz` 모두 호출 노드. 호출자(어느 함수 안에서)와
  피호출자(무슨 이름) 쌍을 뽑음.
- **동적 디스패치** — `call_user_func($x)`, `obj[key]()`, `$this->{$m}()`, `getattr(o,n)()`,
  `send(m)`. 정규식이 통째로 놓치던 것들임. tree-sitter 경로에서만 `syntax="dynamic-call"` ·
  `sink_category="dynamic-call"` 콜사이트로 나옴. 고임팩트 버그가 숨는 자리라 이걸 보려고 파스
  트리로 갈아탄 것.

정규식은 `function`이라는 단어는 잡아도 이게 정의인지 문자열 안인지 주석인지를 구분 못 함. 파스
트리는 문법적으로 정확해서 주석·문자열·중첩을 헷갈리지 않음. 콜그래프 정확도가 여기서 갈림.

### 1-2. 콜그래프 — `누가 무엇을 호출하는가`

추출한 (호출자→피호출자) 쌍을 모아 **콜그래프(call_graph)**를 만듦. 피호출자 이름을 정의 위치(어느
파일의 어느 함수)로 해소(resolve)해서 파일·함수를 잇는 엣지로 바꿈. 이게 데이터 흐름 추적의
지도임. A(인젝션)는 이걸 **거꾸로** 타서 sink→source 역추적을 하고 B(접근제어)는 entry→자원으로
따라감.

특별 취급이 하나 있음. **위험한 내장 함수 호출은 `<builtin-sink>` 엣지로 따로 표시**함.
`query`/`exec`/`system`/`unserialize`/`eval`/`include`/`require`/`file_get_contents`/`curl_exec`
등. `include`·`require`·`eval`처럼 괄호 없는 언어 구문은 일반 호출로 안 잡혀서 별도 규칙으로 sink
엣지를 만듦. A가 "위험지점이 어디 있나"를 콜그래프 조회 한 번으로 열거할 수 있게 됨.

`callgraph.py`로 질의함:

```bash
callgraph.py --stats                 # 엣지/sink 수 (0이면 구조 빌드 실패)
callgraph.py --entries               # entry point 목록
callgraph.py --sinks                 # sink 엣지 목록
callgraph.py --callers <sink>        # 누가 부르나
callgraph.py --callees <handler>     # 이 핸들러가 뭘 부르나
callgraph.py --trace   <sink> -d 8   # sink에서 entry까지 역방향 경로
callgraph.py --forward <source> -d 8 # source가 어디로 흘러가나
callgraph.py --model workspace/cm/<name>.json --sinks   # 모듈별 모델에 질의
```

`--stats`는 `_model_stats.json` 사이드카를 먼저 보기 때문에 GB급 모델을 통째로 열지 않고도 카운트가
나옴.

### 1-3. entry point 추출 — 공격자가 들어오는 문

콜그래프만으론 "어디가 외부 입력 진입점인가"를 모름. 그래서 **라우트/핸들러 패턴으로 entry point를
따로 뽑음**. 실제로 들어 있는 패턴:

- Python 데코레이터: `@app.route`, `@router.get/post/put/patch/delete/head/options`
- Spring: `@GetMapping`, `@PostMapping`, `@RequestMapping`
- Express/Koa/Go: `app.get("/x")`, `router.post(...)`, `r.HandleFunc(...)`, `mux.Handle(...)`
  (`use`/`all`/`handle` 계열은 메서드 `ANY`로)
- PHP: `Route::get('/x', ...)`, `Route::match(...)`
- Rails 라우트: `get '/x', to: 'posts#show'`
- Ruby 컨트롤러 액션: 파일 경로에 `controller`/`route`가 들어간 파일의
  `index`/`show`/`create`/`update`/`destroy`/`new`/`edit`

클라이언트 JS는 일부러 뺌. `assets/`·`javascripts/`·`frontend/`·`webpack/`·`client/`·`public/`·
`static/`·`spec/`·`test/`·`node_modules/` 아래의 JS·TS에서 `router.get('/x')`를 잡으면 Vue/React
라우터 수천 개가 "entry point"로 올라와 진짜 서버 라우트를 덮어버림. 서버 측 JS는 그 디렉토리 밖에
있으니 손해가 없음.

### 1-4. 커버리지 = 계층 트리 (디렉토리 → 모듈 → entry point)

커버리지를 평평한 모듈 리스트로 재면 깡통 `vendor/`도 헬퍼 라이브러리도 라우트 빽빽한 API
디렉토리도 전부 동등한 한 칸이 됨. "다음 볼 것"을 알파벳 순으로 주니 정작 중요한 API가 뒷전으로
밀림. 그렇게 나온 "100% 커버리지"는 "모든 파일 한 번 훑음"이라는 뜻밖에 안 됨. 그래서
**공격표면 트리**로 모델링함:

- **모듈 분할** — 디렉토리를 모듈로 쪼개되 한 모듈이 너무 크면(`TF_SPLIT_THRESHOLD`, 기본 120파일)
  자식 디렉토리로 더 쪼갬. 깊이는 `TF_MAX_DEPTH`(기본 4)까지. 깊고 큰 코드베이스도 잘게 들어감.
- **각 모듈에 entry point 부착** — CODE_MODEL의 entry point를 그 파일이 속한 모듈에 매달음. 모듈마다
  "이 안에 어떤 라우트가 있다"가 붙으니 커버리지가 *디스크의 파일*이 아니라 *도달 가능한
  공격표면*을 반영함.
- **`--next`는 공격표면 우선** — pending 모듈 중 entry point 있는 것(라우트 노출)을 leaf 라이브러리보다
  먼저, entry point 많은 순으로 줌. 여기에 심층 분석 가점이 얹힘(아래 4.6-3).
- **`--tree`** — 디렉토리→모듈→entry point 계층을 status(✓/·)와 함께 출력. 각 라우트
  (`→ POST resume  ...:line`)까지 보여서 A/B가 "이 라우트에서 안쪽으로 추적"을 바로 시작할 수 있음.
- **`--summary`에 공격표면 별도 추적** — "모듈 N/M 분석"뿐 아니라 "entry-point 모듈 N/M 분석"을 따로
  보고. 라이브러리를 다 봤느냐가 아니라 라우트를 다 봤느냐가 진짜 지표.

**왜 이렇게 함**: 코드를 통째로 LLM에 던지면 컨텍스트에 안 들어가고 멀리 떨어진 source·sink 연결을
놓치고 "다 봤다"는 보장도 없음. 그래서 기계적 구조추출(AST·콜그래프·entry point)은 툴이 한 번에
정확히 하고 LLM은 그 지도 위에서 판단만 함. 커버리지를 트리로 만든 건 무한정 넓은 코드에서
**공격자가 실제 도달하는 경로부터** 유한한 우선순위로 훑게 하려는 것.

### 1-5. proof ledger와 모듈별 모델 — 큰 타깃을 다루는 법

`proof_ledger.json`은 route 유닛과 sink 유닛을 하나씩 세워두고 각각의 `status`·`verdict`·`evidence`를
들고 있는 원장임. 긴 분석의 구조적 기억 장치라고 보면 됨.

```bash
proof_ledger.py --summary
proof_ledger.py --next route            # 위험 가점 높은 미처리 유닛부터
proof_ledger.py --show <unit_id>
proof_ledger.py --done <unit_id> --verdict safe --evidence "<어떤 체크가 막는지>"
proof_ledger.py --done <unit_id> --verdict finding --finding <finding_id>
```

두 군데에 게이트가 걸려 있음. `--verdict safe`는 `--evidence`로 무엇이 이걸 안전하게 만드는지를
적어야 통과함(10자 미만이면 거부). `--verdict finding`은 `--finding <id>`가 가리키는 파일이
`workspace/findings/`에 실제로 있어야 함. 근거 없는 "안전"과 기억에만 있는 finding id를 막으려는 것.

분석 가능 파일이 4000개(`TF_GRAPH_ONLY_FILES`)를 넘으면 `build_code_model.sh`가 **graph-only** 추출로
내려감. graph-only에는 데이터플로우도 sink 집합도 proof ledger도 없는데, 그게 A와 B가 실제로
질의하는 내용의 대부분임. 그래서 `seed.sh`에 `name:path` 한 줄씩 적은 모듈 파일을 넘기면 보안
경계를 지고 있는 영역마다 풀 모델을 따로 빌드함(`TF_SEED_JOBS`, 기본 6개 병렬):

```bash
callgraph.py    --model  workspace/cm/<name>.json --sinks
proof_ledger.py --ledger workspace/cm/<name>.proof_ledger.json --next route
```

모듈 파일에는 라우팅·인증·관리자·API 표면·파서·템플릿/렌더·업로드·플러그인 로딩처럼 경계를 지는
영역만 골라 적음. 이번 버전에 없는 경로는 건너뛰므로 파일 하나가 릴리스를 넘어 계속 쓰임.

### 1-6. campaigns/ — 타깃별 설정은 하네스 밖에

타깃 하나를 어떤 체크아웃·URL·계정·모듈 구성으로 볼지는 하네스가 아니라 설정임. 그래서
`campaigns/`에 파일 두 개로 분리해 둠.

| 파일 | 내용 |
|---|---|
| `<name>.modules` | `name:path` 한 줄씩. 각각 `workspace/cm/<name>.json`에 풀 모델이 생김 |
| `<name>.sh` | 타깃·URL·계정·백엔드·모델·canary 환경변수 + `TAINTFORGE_EXTRA_CONTEXT`, 끝에 `exec ./start.sh ...` |

```bash
./seed.sh targets/<app> campaigns/<name>.modules   # 체크아웃당 한 번
./campaigns/<name>.sh                              # 역할 실행
```

git에는 `README.md`와 `example.*` 한 쌍만 올라가고 나머지 캠페인은 로컬에 남음.
`TAINTFORGE_EXTRA_CONTEXT`에는 역할이 싸게 알아낼 수 없는 타깃 사실만 넣음. 분석 중인 정확한
태그/커밋, 라이브 인스턴스의 로그인 라우트와 CSRF 방식, 계정별 권한, **이 스택에서 추출기가 못 보는
것**(예: PHP의 `add_action`/`apply_filters` 훅 디스패치, 가변 함수, `call_user_func`), 이 벤더의
공개 이력이 실제로 어디 쌓이는지. 방법론을 여기서 다시 설명하기 시작하면 그건 이미 설정이 아님.

---

## 1.5 모든 역할을 묶는 방법론

`.agents/skills/_shared/METHODOLOGY.md`는 언어·타깃·취약점 클래스에 독립적인 계약임. 모든 역할이
`AGENTS.md` 다음, 자기 역할 스킬 앞에 이걸 읽음.

> **이 절은 그 파일의 한국어 요약임. 단일 진실 원천은 `METHODOLOGY.md` 쪽임.** 둘이 어긋나면
> 영문 쪽이 맞고, 이 절이 낡은 것임. 역할이 실제로 먹는 건 영문 파일이라서 그럼. 방법론을
> 고칠 때는 `METHODOLOGY.md`를 먼저 고치고 여기를 따라 맞출 것.

### 1.5-1. 전제 둘

**전제 1 — 다리 세 개.** 대부분의 분석가와 모든 툴은 source에 편향되거나, sink에 편향되거나,
전파(propagation)를 건너뛰어서 버그를 놓침. 흐름 모양의 결함은 세 다리가 전부 명시적으로 적혔을
때만 존재함. 가정한 다리는 finding이 아니라 lead임.

**전제 2 — 모양 둘.** 결함은 두 모양으로 옴.

- **(A) 위험한 흐름** — 오염된 값이 위험한 연산에 닿음
- **(B) 빠진 통제** — 도달 가능한 경로에 있어야 할 체크가 없음

접근제어·인증·대부분의 로직 버그는 (B) 모양임. (A)만 사냥하면 (B)를 통째로 잃음. **트랙 이름은
클래스가 아니라 모양에서 왔음.** Track A가 흐름 트랙, Track B가 부재 트랙. 어떤 클래스든 두 모양을
다 가질 수 있으니 모양부터 정하고 라우팅함. finding에는 `defect_shape: "flow" | "missing_control"`로
적음.

### 1.5-2. 위협 모델 먼저

사냥 전에 네 가지를 적어둠. 각자 워크스페이스에 자리가 있음.

| 무엇 | 어디 | 누가 |
|---|---|---|
| entry point | `CODE_MODEL.structural.entry_points`, `proof_ledger.json` | `build_code_model.sh` |
| 행위자·신뢰 경계 | `CODE_MODEL.comprehension.{route_map,permission_model,trust_boundaries}` | source-model (에이전트) |
| 자산 | `CODE_MODEL.comprehension.service_identity.sensitive_data` | source-model (에이전트) |
| 불변식 | `HYPOTHESES.json` (`invariant` + `attacker_goal`) | hypothesize (에이전트) |

entry point에는 라우트·핸들러·RPC·큐 컨슈머·CLI·웹훅·크론·파일 파서·역직렬화 입구·IPC·프로토콜 와이어
리더가 다 들어감. 행위자는 미인증/인증됨/역할별/테넌트별/내부 서비스로 나누되, entry point마다
*누가 여기 닿는가*를 라우트 이름에서 짐작하지 말고 호출 체인으로 증명함. 불변식은 코드가 말없이
참이라고 믿는 것들임 — 소유권, `balance >= 0`, 상태 기계 순서, "여기선 이미 인증됨", "이 포인터는
살아 있음". **불변식 목록이 곧 후보 버그 목록.** entry point × 최소 권한 표가 안 나왔으면 위협
모델은 안 한 것임. 모든 finding의 `reachability`가 그 표에서 파생됨.

### 1.5-3. SOURCE 여덟 계열

"입력"이 아니라 "공격자의 영향력"으로 봄. 4~8번은 taint 엔진에도 구조적 콜그래프에도 안 보임.
수명과 오류 경로를 읽어야만 나옴.

1. **직접 입력** — 요청 파라미터·헤더·쿠키·바디, 업로드, env, IPC, 역직렬화 바이트, 파일, 프로토콜 프레임
2. **신원·인가 상태** — 세션, 토큰, 역할, 테넌트 id, 소유자 id. 공격자가 *고르거나 위조하거나
   헷갈리게 만들 수 있는* 전부. 신원을 공격자 영향력이 아니라 믿을 만한 문맥으로 취급하는 게 (B)
   모양을 놓치는 제일 흔한 이유
3. **2차·저장된 값** — DB·캐시·설정·로그에 썼다가 나중에 신뢰하고 읽는 값(stored XSS, 2차 인젝션,
   로그→템플릿)
4. **해제 후 리셋 안 된 상태** — free/close 했는데 전역·구조체 필드·레지스트리가 여전히 참조하는
   포인터·핸들·fd·객체. UAF의 뿌리
5. **bailout으로 고아가 된 상태** — 예외·`longjmp`·panic·조기 반환·OOM·타임아웃이 정리를 건너뛰어
   남은 상태. 정상 경로는 깨끗하고 오류 경로가 더러움
6. **스코프를 넘는 영속 상태** — 요청 간(워커/프로세스 재사용), 스레드 간, 워커 간(공유 메모리),
   캐시 경유로 운반됨
7. **미초기화 재사용·메타데이터 불일치** — 풀/아레나 잔류물, 자기가 설명하는 객체와 어긋난 길이·타입·
   소유권·refcount 필드
8. **시간과 순서** — 동시 인터리빙, 재진입, nonce/토큰/일회성 액션 재생. 모든 TOCTOU와 레이스의 source 다리

### 1.5-4. 클래스 × 모양 매트릭스

클래스마다 두 모양이 다 존재함. 담당 열은 A와 B 사이로 클래스가 떨어지지 않게 하려고 있음.

| 클래스 | (A) 위험한 흐름 | (B) 빠진 통제 | 담당 |
|---|---|---|---|
| 접근제어/authz | 입력의 객체 id → 소유권 체크 없이 로드/변경 | 모든 권한 연산 경로에 authz 체크가 있나, 수평/수직 상승, 테넌트 격리 | B |
| 인증 | 토큰·세션 값을 검증 없이 신뢰 | 인증 우회, 약하거나 고정된 세션, MFA 건너뛰는 경로 | B |
| 인젝션 | 입력 → SQL/NoSQL/cmd/code/LDAP/템플릿/XSS/CRLF | 파라미터 바인딩 없음, 문맥에 맞는 인코딩 없음 | A |
| SSRF/요청 위조 | 입력 URL → 서버 측 fetch(http/dns/socket) | 목적지 allowlist·메타데이터 IP 차단 없음, CSRF 토큰 없음 | A(SSRF) / B(CSRF) |
| 경로·파일 | 입력 → 경로(traversal/LFI/RFI), 업로드 이름·타입 | 정규화 없음, 루트 밖 탈출 허용, 타입 체크 없음 | A |
| 역직렬화/객체 주입 | 신뢰 못 할 바이트 → `unserialize`/`pickle`/가젯 | 타입 allowlist 없음, 서명 없음 | A |
| 메모리 안전 | 입력이나 해제 후 상태 → `memcpy`/인덱스/역참조/함수 포인터 | 길이·NULL·수명 가드 없음(UAF/OOB/타입 혼동) | A |
| 동시성/TOCTOU | 체크와 사용 사이에 공유 상태가 바뀜 | 락 없음, 원자성 없음, 멱등성 없음 | B(로직·상태) / A(메모리·수명) |
| 암호 | 비밀·입력 → 약한 알고리즘, 고정 IV, 비상수시간 비교 | 검증 없음, 예측 가능한 난수, 평문 저장 | B |
| 자원/DoS | 입력 크기·개수 → 무제한 할당·루프·재귀 | fd/락/메모리 미반납, rate limit·쿼터 없음 | A(흐름) / B(부재) |
| 정보 노출 | 내부 상태·비밀 → 응답, 에러, 로그, 타이밍, 쿠키 | 마스킹 없음, 최소화 없음, 디버그 표면 켜짐 | A |
| 비즈니스 로직 | 입력 → 불변식 위반(음수 수량·가격, 순서 역전, 재생) | 상태 기계 없음, 한도 없음, 멱등성 없음, 서버 측 검증 없음 | B |
| 설정/공급망 | — (거의 항상 부재) | 기본 자격증명, 과도한 권한, 안전하지 않은 기본값, 오염된 의존성 | B |

주인 없는 클래스는 없음. 어느 트랙도 명백히 자기 것이 아니면 찾은 역할이 `defect_shape`를 세우고
왜 여기 있는지 한 줄 달아서 파일함. A는 "로직처럼 보인다"고 버리면 안 되고 B는 "인젝션처럼
보인다"고 버리면 안 됨. 일단 파일하고 `correlation_id`를 세우면 C가 중복을 정리함.

### 1.5-5. SINK 일곱 그룹과 사각지대

1. **실행** — `system`/`exec`/`eval`/`popen`, `include`/`require`, 역직렬화, 템플릿 렌더, 동적 import/플러그인 로드
2. **질의·저장** — SQL/NoSQL/ORM raw, 파일 쓰기, 외부 API 호출
3. **네트워크** — 서버 측 fetch(http/socket/dns) → SSRF
4. **노출 출력** — 응답 헤더, 쿠키, 바디, 에러 메시지, 로그, URL 재작성, **타이밍**
5. **메모리** — `memcpy`/`memmove`/`strcpy`(길이·오프셋), 배열 인덱스, 포인터 연산, 역참조, 함수 포인터
6. **권한·제어** — 역할/소유권/플래그 쓰기, vtable/핸들러/디스패치 테이블, 리다이렉트 목적지
7. **자원** — 무제한 할당·루프·재귀, 락/fd 획득

> **알려진 사각지대.** `build_code_model.sh`가 세우는 구조적 sink 집합은 고신호 범주만 담음
> (sql / command / code-eval / deserialization / file-path / ssrf-net / redirect). 4·5·6·7 그룹은
> 기본 원장에 **없음**. `TF_NOISY_SINKS=1`로 다시 빌드하거나 `callgraph.py --callers <symbol>`로
> 직접 열거해야 함. 그 네 그룹에 대해 "원장에 sink가 없었다"는 안전의 근거가 못 됨.

### 1.5-6. 전파와 도달성 — 데이터 흐름이 아닌 엣지들

taint는 엣지 한 종류일 뿐임. 여섯 가지를 다 따라가야 함 — 신뢰 경계 전이, 제어 흐름 건너뛰기,
수명 엣지, 스코프 전이, 동시성 인터리빙, 양방향 콜그래프.

신뢰 경계 전이는 미인증에서 인증 자원으로, 테넌트 A에서 테넌트 B로, 저신뢰 저장소에서 고신뢰
소비자로 넘어가는 자리임. 제어 흐름 건너뛰기는 예외·bailout·`longjmp`·조기 반환·재시도가 체크나
정리를 뛰어넘는 경우임. 정상 경로의 체크가 오류 경로엔 없을 수 있으니 오류 경로를 따로 추적해야
함(P6). 수명 엣지는 alloc → free → 같은 주소 재할당, 즉 UAF가 사는 자리인데 고전적 taint 분석은
이걸 못 봄. 스코프 전이에서는 요청 A가 오염시킨 상태를 요청 B나 워커 B, 혹은 나중에 도는 잡이
소비함. 동시성 인터리빙은 체크와 실행 사이에 다른 스레드가 끼어드는 것. 마지막으로 양방향
콜그래프는 각 source에서 앞으로 *어디로 떨어지나*를, 각 위험 연산에서 뒤로 *뭐가 닿나*를 둘 다
보는 일임. 한 방향만 하면 그게 바로 전제 1의 source/sink 편향임. 처음과 끝을 뺀 가운데 넷은
그래프에 안 들어 있으니 코드를 읽어야 나옴.

### 1.5-7. 필수 패스 일곱 — 하나 건너뛰면 그 계열 전체를 놓침

`proof_ledger.py --next` / `coverage.py --next`가 몰아주는 대로 전부 소진할 때까지 돌림. 감으로
멈추지 않음.

| # | 패스 | "끝났다"의 기준 | 담당 |
|---|---|---|---|
| P1 | **entry × 권한 지도** — entry point마다 거기 닿는 최소 권한과 그 권한이 건드리는 민감 연산. pre-auth 도달성은 호출 체인으로 증명 | 원장의 모든 route 유닛에 권한이 붙음 | B |
| P2 | **권한 연산 가드 감사**(shape B) — 소유권·역할·상태·결제가 필요한 연산마다, *그 경로*에 *모든 호출자*에 체크가 실제로 앉아 있나 | 모든 권한 연산이 finding / safe+근거 / needs_reanalysis 중 하나 | B |
| P3 | **불변식 위반 스윕** — 1.5-2의 불변식마다 그걸 깨는 입력·순서·동시성이 있나 | `HYPOTHESES.json`의 모든 불변식이 검증 또는 반증됨 | B |
| P4 | **장수명 수명 스윕** — 포인터·핸들·fd·락을 쥔 전역·장수명 필드마다 (a) 어디서 해제되나 (b) 어디서 리셋되나 (c) 그 사이에 bailout이 가능한가. 셋 다 참이면 후보 | 그런 필드 전부 분류됨 | A |
| P5 | **taint → 모든 sink 계열** — 1.5-3의 source를 1.5-5의 **일곱 그룹 전부**로 흘려봄. 특히 노출 sink(헤더·쿠키·로그·타이밍)와 SSRF | 열거된 모든 sink 유닛에 처분이 달림 | A |
| P6 | **오류/예외 경로 diff** — 성공 경로에서 도는 체크·정리 집합과 실패 경로의 집합을 비교. 빠진 체크는 우회, 빠진 해제는 누수나 댕글링 | 실패 경로가 있는 모든 가드 연산을 비교함 | A + B |
| P7 | **스코프 교차·동시성 토폴로지** — 요청 재사용·워커 재사용·동시 실행을 가정하고 도달성을 다시 판정 | 모든 상태 연산을 재사용 가정하에 판정 | A + B |

P4·P6·P7은 이 저장소에 툴 지원이 없음. 코드를 읽는 패스임. 스캐너를 피해 살아남은 버그가 거기 삶.

### 1.5-8. 가드레일

- **두 모양 다 돌릴 것.** source→sink만 쫓으면 접근제어·인증·로직이 통째로 빠짐.
- **source만으로 판정 금지.** 정보 누출이나 UAF read는 관측 지점(1.5-5의 4번 그룹)이나 위험 연산에
  닿기 전까진 결함이 아님. 그 다리가 없으면 finding이 아니라 `lead`(`leads.py`)임. 둘 중 뭔지 말해야 함.
- **첫 히트에서 멈추지 말 것.** 결함은 뭉쳐 있음. 같은 시그니처의 다른 인스턴스를 전부 쓸고 넘어감.
- **계측 ≠ 결함.** 새니타이저·디버그 어서션·진단 프로브·패치 빌드에서만 나는 크래시는 lead임. 정확히
  stock 빌드에서 재생해야 finding이 됨. 관측이 어느 빌드에서 나왔는지도 기록함
  (`repro.instrumentation_only`, `repro.stock_replay`).
- **전제조건과 버그를 분리할 것.** 전제조건이 기본/벤더 출하 설정에서 성립하는지 밝히고 아니면 정확히
  어떤 비기본 설정인지 적음(`preconditions`).
- **상승 천장은 증명할 것.** read→write, 크래시→제어, 자기→남의 계정. 단계마다 증명하거나 주장하지
  않음. 안 올라가면 "DoS만", "읽기 전용", "본인 것만"으로 못 박음
  (`primitive.escalation_ceiling`, `primitive.ruled_out`). 과대포장은 그 자체로 보고 결함임.
- **도달성은 entry point *와* 권한.** "누가 이걸 터뜨릴 수 있나"는 호출 체인 + 역할로 답하고 짐작으로
  답하지 않음(`reachability`).
- **한 근본 원인에 한 finding.** 트리거 변종은 같은 finding의 재현 케이스임. 패치 하나로 둘 다 고쳐지면
  하나임. `correlation_id`를 공유함.

### 1.5-9. 출력 계약 — 스키마가 곧 보고 형식

산문 finding은 쓰지 않음. 아래 전부가 `schemas/finding.schema.json`의 필드고 `write_finding.py`를
통해서만 들어감.

| 요소 | 필드 |
|---|---|
| 클래스 태그 + CWE | `vuln_class`, `cwe` |
| 어느 모양인가 | `defect_shape` |
| 메커니즘 | `evidence` |
| SOURCE → SINK | `source`, `sink`, `flow[]` (shape A) |
| 빠진 통제와 그게 빠진 경로 | `missing_control{control,expected_at[],unguarded_path,actor}` (shape B) |
| 도달성(entry point, 권한, pre-auth, 호출 체인) | `reachability{entry_point,min_privilege,pre_auth,call_chain[]}` |
| 전제조건(기본 설정 여부) | `preconditions{default_configuration,required_settings[],notes}` |
| primitive와 상승 천장 | `primitive{kinds[],escalation_ceiling,ruled_out[]}` |
| 영향받는 자산 | `assets_affected[]` |
| 재현과 재현율 | `repro{poc,response,reliability,instrumentation_only,stock_replay}` |
| 배제한 가드 | `sanitizers_seen[]` |

`vuln_class`에 쓰는 클래스 태그(kebab-case): `broken-access-control`, `auth-bypass`, `idor`,
`sql-injection`, `nosql-injection`, `command-injection`, `code-injection`, `ssti`, `xss`, `ssrf`,
`csrf`, `path-traversal`, `deserialization`, `xxe`, `open-redirect`, `use-after-free`, `oob-read`,
`oob-write`, `type-confusion`, `null-deref`, `toctou-race`, `crypto-misuse`, `info-leak`, `dos`,
`business-logic`, `misconfiguration`, `supply-chain`.

---

## 2. 생산자 A — 인젝션 / 데이터 흐름

SQLi, 명령·코드 인젝션, SSTI, 역직렬화, 동적 import·플러그인 로드, 공격자가 제어하는 파일 쓰기·업로드,
실행 가능한 위치로의 경로 순회, 그리고 RCE로 체인될 수 있는 SSRF를 찾음. finding은 track `A`,
`defect_shape`는 보통 `flow`.

- **sink-first(역추적) 방식** — 위험한 연산(sink)에서 시작해 call graph를 **거꾸로** 따라가며 공격자
  입력이 거기 도달하는지 봄. 코드 실행이 가능한 sink를 먼저 잡음. 미인증 입력부터 보고 그다음이 인증 입력.
- 경로상의 sanitizer(이스케이프·검증)를 판단함. sink 자체 파일에선 안전해 보여도 몇 단계 떨어진 곳에서
  오염된 데이터가 들어오는 경우를 잡음.
- 방법론 쪽 숙제도 A 몫임. P5(일곱 sink 그룹 전부로 taint 흘리기), P4(장수명 자원 수명 스윕),
  P6·P7(오류 경로 diff와 재사용 가정)을 `proof_ledger.py --next`가 주는 순서대로 소진함.
- OpenGrep(SAST)이 주는 단서는 `workspace/hints/`에 쌓임. **단서는 "여기 봐라"일 뿐 취약점이 아님.**
  에이전트가 직접 판단해서 작성함.
- 아직 버그가 아닌 중간 능력은 `leads.py`에 적어둠. 이미 `needs_reanalysis`로 찍힌 finding은 E 전담이라
  A가 건드리지 않음.

입력(source)은 코드 어디에나 있어서 정방향 추적은 폭발적으로 퍼지고 대부분 헛다리임. 위험한 연산은
**유한하고 열거 가능**함. 모든 흐름 결함은 결국 sink에서 끝나므로 "이 N개의 위험지점에 오염 데이터가
닿는가?"로 문제를 한정된 체크리스트로 바꾸는 게 sink-first의 요지. 다만 sink 편향에 빠지지 않으려고
P5에서 source 쪽에서도 한 번 밀어봄.

---

## 3. 생산자 B — 로직 / 접근제어

SAST가 못 보는 버그를 찾음. IDOR/BOLA, 권한 누락, 권한 상승, 인증·세션 우회, 비즈니스 로직 결함.
finding은 track `B`, `defect_shape`는 보통 `missing_control`.

- **entry→자원(정방향) 방식** — 라우트(진입점)에서 시작해 자원 접근까지 따라가며 경로 어딘가에
  **인가 게이트**가 있는지 확인함.
- 체인 전체(`핸들러 → 서비스 → 저장소/객체 로드`)를 따라가며 물음. 인증 체크, 역할/권한 체크, 그리고
  **소유권/테넌트 체크**가 있는가?
- 소유권 체크 없이 `findById` 같은 게 라우트에서 도달 가능하면 IDOR. 상태 변경 액션에 역할 체크가
  없으면 접근제어 결함.
- 우선순위는 pre-auth 인증 우회, 그리고 저권한에서 코드를 실행할 수 있는 관리자 기능으로 가는 경로임.
  플러그인 설치·로드, 모델/프로바이더 엔드포인트 변경, 파일 쓰기, 툴 실행, 콜백 등록처럼 RCE 체인을
  완성하는 기능들.
- 부재는 보여줄 taint가 없으므로 증거를 `missing_control{control,expected_at,unguarded_path,actor,evidence}`에
  적음. 어떤 호출자를 열거했고 어느 레이어를 봤고 같은 체크가 어디엔 있는지까지.
- P1(entry × 권한 지도), P2(가드 감사), P3(불변식 스윕)이 B 담당이고 P6·P7은 A와 나눠 가짐.

**왜 별도 트랙**: 인젝션과 정반대 방향이고 툴이 거의 장님임("소유권 체크 누락"은 grep 패턴이 아님).
앱 이해(라우트, 권한 모델)가 필요해서 A와 다른 방법·다른 시드를 씀. 한 세션이 둘 다 하면 쉬운
인젝션에 치우치고 로직 버그를 소홀히 하게 됨.

---

## 4. 소비자 C — 수렴 (검증·재현·제품경계 판정)

A·B가 생산하는 동안 **계속 돌면서** 큐의 finding을 소비함. finding 하나당 단계별로 증명 강도를 높임.
심각도 높은 것부터 집음.

### 4-1. 교차검증

```bash
cross_validate.sh targets/<app> [language]
```

기본은 항상 CodeQL(가장 깊은 절차 간·파일 간 taint)임. CodeQL이 없거나 실패하면 OpenGrep으로
떨어져서 교차검증이 조용히 건너뛰어지는 일이 없게 함. `ENGINE=opengrep`으로 강제할 수도 있음.
이어서 `correlate.py`가 같은 sink를 엔진도 짚은 후보를 `cross_validated`로 올리고 history 항목을
남김. CodeQL에는 PHP 팩이 없음. 그래서 PHP 타깃은 CodeQL 실행 자체가 실패하고 `codeql`이 아예
없을 때와 똑같은 경로로 OpenGrep에 넘어감. 라이선스도 OSI 오픈소스·연구용만 무료임. Track B 로직
finding은 이 단계를 건너뜀 — 재현이 동작을 증명하고 제품경계 게이트가 벤더 버그인지를 판정함.

### 4-2. 라이브 재현 (`-u URL` 줬을 때)

실제 돌아가는 인스턴스에 요청을 쏴서 진짜 터지는지 봄. 취약점 종류별로 도구가 다름.

- **probe.py** — HTTP 요청 도구. `--jar`로 **세션(쿠키)을 유지**함. 에이전트가 코드에서 로그인 흐름을
  직접 파악해 로그인하고 그 세션으로 보호된 자원에 접근함. `--no-redirect`면 `Location`이 그대로 보임.
- **IDOR/접근제어** — 계정 두 개를 각자 jar에 로그인시킨 뒤 **한 계정 세션으로 다른 계정의 자원**을
  요청함. 남의 데이터가 돌아오면 확정. 일반 유저가 둘 이상 필요함. 관리자 계정만으로는 교차 접근을
  증명 못 함.
- **SSRF** — `canary.py`(out-of-band 서버)를 띄워두고 타깃이 `http://<canary>/<토큰>`을 가져오게 만든 뒤
  `canary.py check <토큰>`으로 HIT을 확인함. 콜백이 불가능하면 내부 호스트(`127.0.0.1:<port>`,
  `169.254.169.254`) 응답·타이밍 차이로 비교하거나 이유를 달아 `needs_reanalysis`로 넘김.
- **XSS** — 반사만으론 증명 안 됨. `browser_probe.py`(헤드리스 Chromium)로 **실제 JS가 실행되는지**
  확인함. dialog가 뜨거나 주입한 마커(`window.__tf_xss`)가 돌면 `executed:true`. 실행된 것만 재현 인정.

재현 요청 전문은 `repro.poc`에, 결정적 응답 증거는 `repro.response`에 반드시 붙임. PoC 없으면 재현이
아님. 성공이면 `reproduced`, 반증되면 `false_positive`, 애매하면 `needs_reanalysis`로 넘기고 이유를
history에 남김.

### 4-3. 공식/벤더 제품경계 검토 (필수)

재현은 **동작**을 증명할 뿐 제품 취약점임을 증명하지 않음. 그래서 `reproduced`가 된 모든 finding은
1차 벤더 자료와 대조해야 함. 이 관문을 통과하지 못하면 `confirmed`로 못 감.

대조 항목은 정확한 제품/컴포넌트/버전과 지원 여부, 기본·벤더 생성 설정 대 앱이 직접 쓴 위험한 설정,
문서화된 보안 경계·API 계약·미들웨어 순서·호출자 의무, 결정적 sink가 제품 것인지 PoC 앱이 추가한
것인지, 그리고 의도된 동작을 보여주는 버전별 소스 테스트·패치·릴리스 노트·어드바이저리.

결과는 `official_review{checked,verdict,sources,rationale,product_version,default_configuration}`로 적음.
`sources`에는 1차 공식/벤더 문서, 보안 가이드·어드바이저리, 릴리스/패치 자료, 벤더 소유 저장소의
이슈·디스커션 중 하나 이상의 **공개 HTTPS URL**이 들어가야 함. 로컬 소스 경로와 GitHub `blob`/`tree`/raw
링크는 보조 증거일 뿐 이 게이트를 혼자 통과하지 못함. `rationale`은 공식 자료와 PoC를 직접 비교해서
어떤 보안 불변식이 깨졌는지, 혹은 왜 제품 버그가 아닌지를 적음.

판정과 상태 매핑:

- `product_vulnerability` 또는 `known_vulnerability` → `confirmed`
- `documented_hazard`, `expected_behavior`, `application_misconfiguration`, `unsupported_scenario`
  → `not_product_vulnerability`
- `inconclusive` → `reproduced`에 그대로 두고 뭐가 모자란지 기록. 보고 대상도, 0-day 후보도, D로
  넘길 대상도 아님

성공한 요청, 인증 우회 관측, 크래시, 프로세스 생성 그 자체는 벤더 제품 취약점의 증거가 아님. 공식
문서가 바로 그 미들웨어 순서를 위험하다고 경고하며 안전한 순서를 제시하고 있다면 그건
`documented_hazard`지 새 프레임워크 취약점이 아님. 반대로 문서가 없다는 사실만으로 취약점이 되지도
않으니, 재현된 동작이 깨뜨린 지원 보안 불변식을 지목해야 함.

### 4-4. 증거 계약 (`confirmed`에서 강제)

제품경계 검토가 "이 동작은 실재하고 벤더의 것"임을 말한다면, 증거 계약은 "그 동작이 읽는 사람에게
무엇인지"를 말함. `confirmed`로 올리는 바로 그 `--update`에 같이 넣어야 하고 `write_finding.py`가
빠진 걸 거부함.

- `defect_shape` — `flow`(세 다리 전부) 또는 `missing_control`(+ `missing_control{...}`). 생산자가
  비워놨다면 모양을 끝내 안 정했다는 뜻이니 이야기가 서는지 다시 봄.
- `reachability{entry_point,min_privilege,pre_auth,call_chain}` — 누가 어떤 권한으로 터뜨리는지를 체인으로
  증명. 생산자가 pre-auth라고 했으면 미인증 요청으로 직접 확인하고 아니면 실제 재현한 수준으로
  `min_privilege`를 내림.
- `preconditions{default_configuration,required_settings}` — 기본/벤더 출하 설정에서 재현했을 때만 true.
  플러그인·플래그·비기본 설정을 켜야 했으면 그대로 나열함. `official_review.default_configuration`과 같은
  판단이고 둘이 어긋나면 안 됨.
- `primitive{kinds,escalation_ceiling,ruled_out}` — 증명한 능력과 정직한 상한. *해봤는데 안 된* 상승은
  이유와 함께 `ruled_out`에, 아예 안 해본 상승은 rule-out이 아니며 주장하지도 않음. 천장은 나중에 D가
  증거를 들고 올림.
- `repro{reliability,instrumentation_only,stock_replay}` — 얼마나 재현되는지(레이스·힙 상태 의존 버그엔
  필수), 그리고 그 관측이 새니타이저·디버그 어서션·패치 빌드·진단 프로브에서만 존재했는지.
  그런 관측은 `stock_replay`에 정확한 stock 빌드 실행이 기록되기 전까지 **lead**임. writer가 이걸 강제함.

과대포장은 보고 결함이고 한계 없는 주장은 벤더가 진짜 버그를 닫게 만드는 가장 쉬운 길임. "읽기 전용,
본인 소유 객체만"이 "권한 상승이 가능할 수 있음"보다 나은 finding.

### 4-5. 공개 이력 검색 (confirmed 제품 취약점만)

제품경계 검토를 통과해 `confirmed`가 된 다음에야 이게 이미 알려진 건지 새 발견인지를 따짐. 사다리는
네 칸.

1. 증명에서 패치 지문을 뽑음. 영향받는 파일 경로, 클래스/메서드, 헬퍼나 검증 플래그, 거부 사유·에러
   문자열, 특징적인 리터럴, 깨진 프로토콜 불변식. 그 앵커로 소스 이력을 검색함
   (`git log -S'<literal>' -- <path>`와 `git log -G'<semantic-regex>' -- <path>`, 얕은 체크아웃이면
   벤더 저장소 커밋 이력/API).
2. 테스트한 태그를 upstream main 및 해당하는 모든 지원 릴리스 브랜치와 비교함. 걸리는 diff가 있으면
   연결된 이슈·PR·체리픽·서비싱 PR·백포트를 따라감.
3. 벤더 저장소의 **열린·닫힌 이슈**와 **열린·머지된 PR**을 정확한 심볼, 파일명, 검증 플래그, 에러
   문자열, 프로토콜 용어, 그리고 의미가 같은 다른 표현으로 검색함. 제안 취약점 제목만 넣고 끝내지 않음.
4. 벤더 어드바이저리, 보안 어드바이저리, CVE, 릴리스 노트, 서비싱 노트, 체인지로그. 이건 마지막 칸이지
   검토 전체가 아님.

증거는 `disclosure.public_history`에 보관함. 정규 `upstream_repository`, `exact_anchors` 두 개 이상,
`source_history`, `vendor_issues_prs`, `advisories_releases`, 그리고 `head_or_release_comparison`.
그다음 `disclosure.status`를 정함.

- `known` — 같은 근본 원인에 맞는 공개 이슈·PR·커밋·패치·테스트·어드바이저리·CVE·릴리스 노트·체인지로그가
  있음. 보안 라벨이나 CVE가 없는 소스 수정도 `known`임
- `novel` — 사다리를 다 돌았는데 정확히 맞는 게 없고 구조화된 증거도 완전함. **잠재 0-day**
- `inconclusive` — 판단 불가

`write_finding.py`는 이 증거 없는 `novel`을 거부하고 triage와 대시보드는 공개 이력 게이트가 불완전한
항목에서 0-day 라벨을 숨김. `disclosure.status=novel`만 적혀 있는 옛 finding도 마찬가지. 증명 안 된
후보에 이 검색을 쓰지는 않음 — 가장 강한 주장에 가장 많은 검증을 붙이려는 것.

### 4-6. PoC 작성 + 개별 보고서

제품경계 판정이 `product_vulnerability`나 `known_vulnerability`인 `confirmed` finding마다 에이전트가 그
버그에 맞는 `poc.py`를 작성함(requests 사용). pre-auth면 로그인 없이, 다단계면 필요한 만큼, PASS/FAIL
출력. 전체 소스를 `repro.poc_script`에 넣고 `emit_poc.py`를 돌리면 취약점별 폴더가 생김:

```
workspace/report/<id>/poc.py        # 단독 실행 가능, python3 poc.py로 재현
workspace/report/<id>/finding.md    # 그 취약점 하나의 개별 보고서
```

취약점별로 분리 관리함(합치지 않음). `report.md`는 전체 랭킹 인덱스로 남김.

### 4-7. 트리아지

```bash
triage.py
```

큐 현황(상태별 카운트)을 찍고 `workspace/report/report.md`를 다시 씀. 심각도 × 신뢰도(status)로
랭킹하고 `correlation_id`로 중복을 접고 CWE를 OWASP Top 10에 매핑함. false positive와 제품 버그가 아닌
항목은 랭킹에서 빠짐. 보고서 섹션 구성:

```
Summary by status / Summary by class
Official/vendor review pending
Public-history/disclosure review pending
⚠️ Potential 0-day (officially reviewed product vulnerabilities)
💥 Weaponized / chained exploits
Reproduced but not a product vulnerability
Provisional findings (not reportable)
Ranked confirmed product vulnerabilities
Confirmed product vulnerability details
```

공식 검토를 기다리는 재현 항목은 별도 pending 섹션에 들어가고 절대 0-day로 올라가지 않음. 대시보드가
몇 초마다 `triage.py`와 `emit_poc.py`를 다시 돌려서 보고서와 폴더가 묵지 않게 함.

---

## 4.5 익스플로잇 — 에이전트 D (크리티컬 건 무기화)

C가 제품 취약점으로 확정한 것만 **D**가 받아 **완전히 이해된 익스플로잇으로** 끌어올림. 계속 루프:

- **선택** — `confirmed`이면서 `official_review.verdict`가 `product_vulnerability` 또는
  `known_vulnerability`이고 크리티컬 클래스인 것만(RCE, 명령주입, SQLi, 인증우회, 역직렬화, 내부SSRF).
  재현만 된 것, 검토가 `inconclusive`인 것, low/medium은 D 일이 아님.
- **심화 (각 단계 실측)** — 증명된 primitive에서 출발해 **최대 임팩트까지 체인**. 블라인드 SQLi→불린/타임
  추출, 단일토큰 명령주입→경로로 페이로드 파일 실행, SSRF→내부/메타데이터, 인증우회→관리자 액션.
  순서는 pre-auth RCE가 먼저, 인증된 RCE가 그다음. **방어 우회** — sanitizer/이스케이프/따옴표가 막으면
  *정확히 뭐가 통과하는지* 분석해서 실제로 실행되는 우회를 찾음. 말로 때우지 않음.
- **정직하게 기록** — `exploit` 객체에
  `{depth, primitive, max_impact, steps, mitigations_bypassed, constraints, working_poc, oob_evidence}`.
  임팩트가 제한적이면(예: 인자 없는 단일 명령만 실행) 그 한계를 `constraints`에 그대로 적음.
  **정확한 "제한적" 결과가 과장된 것보다 가치 있음.**
- **산출** — `report/<id>/exploit.py`(C의 poc.py와 별도). triage의 💥 무기화 섹션과 대시보드 카운터에 뜸.

`write_finding.py`도 같은 선을 지킴. `exploit` 객체를 추가하거나 바꾸려면 상태가 `confirmed`이고 공식
검토 판정이 보고 가능해야 함. 아니면 쓰기가 거부됨.

**왜 별도 에이전트**: 재현(C)과 무기화(D)는 사고방식도 시간예산도 다름. C는 큐 전체를 계속 흘려보내야
하고 D는 소수에 깊이 파고듦. 분리하면 C가 어려운 익스플로잇 하나에 막혀 있는 동안 늦게 오는 finding이
쌓이는 걸 막음. D는 가리킨 타깃만 침 — 본인 소유이거나 허가받은 자산 전용.

---

## 4.6 심층 분석 — 훑지 말고 타고타고 엮기

성숙한 코드의 고위험 버그는 대부분 **단일 sink가 아니라 체인**임. 그 자체론 무해한 단계들(어떤 함수가
raw 참조 반환, 다른 데서 `hasOwnProperty` 누락, 끝에 도달 가능한 위험 생성자)이 **조합됐을 때만**
취약점이 됨. "sink 찾고 판정하고 넘어가는" 한 번 훑기로는 안 잡힘. 어느 한 줄도 "그 sink"가 아니니까.
연구원이 파서/역직렬화 코드를 한 줄씩 읽으며 "공격자가 이 값을 제어하면 다음 뭐가 되나"를 계속 묻고
얻은 능력을 들고 다음으로 가는, 그 방식을 시스템이 하게 만드는 게 이 단계.

세 가지 메커니즘으로 받침.

### 4.6-1. 깊이 우선 지시 (모든 역할 공통 지침에 박힘)

파싱·역직렬화·이름 기반 디스패치·리플렉션·사용자 제어 속성 경로 walk 하는 코드를 만나면 "알려진 sink
있나"에서 멈추지 말고 한 줄씩 읽으며 매 단계 "이 값 제어하면 다음 뭐가 가능?"을 묻고 그 능력을 들고
전진.

### 4.6-2. lead 노트북 (`.agents/skills/_shared/leads.py`)

한 번 훑기면 버릴 중간 발견을 기록함. `write_finding.py`처럼 파일락이 걸려 있음.

- **lead** — 취약점은 아니지만 흥미로운 관찰. 무엇을 `enables`하는지 같이 적음
- **primitive** — 확보한 능력 (확인된 lead)
- **note** — 한 대상의 진행 상태(이해/확보/다음). respawn을 넘어 이어서 더 깊이 파려고 있음
- **link** — lead들을 체인 후보로 묶음

```bash
leads.py add                      # kind=lead 또는 primitive
leads.py list [--kind lead|primitive]
leads.py open                     # 아직 조합 가능한 것
leads.py note <target> --set "..."
leads.py link <id> <id> ...
leads.py update <id> --status open|combined|dead|promoted [--reason ...]
```

데이터는 `workspace/leads.json` + `workspace/_analysis_notes.json`.

### 4.6-3. 깊이 팔 대상 우선순위

`coverage.py --next`는 공격표면 우선순위 위에 심층 가점을 얹음. 경로에
`pars`/`deserial`/`serial`/`unmarshal`/`decode`/`reviv`/`reflect`/`dispatch`/`router`/`resolver`/
`template`/`render`/`eval`/`interpret`/`marshal`/`rpc`/`gadget` 냄새가 나는 모듈이 먼저 올라옴. 체인이
숨는 곳이고 유한한 분석 시간을 조합 버그가 사는 자리에 쓰려는 배치임.

C(수렴)와 D(익스플로잇)가 체인 후보를 읽어 진입점에서 최종까지 실현하고 하나의 체인 finding으로 묶음.
**lead는 그 자체론 절대 finding이 아니고 버그 아니라고 버리지도 않음** — 다른 세션이 짜는 체인의 빠진
조각일 수 있으니까. 대가는 비용임. 깊이 읽기는 훑기보다 훨씬 비싸서, coverage가 보상 가능성 높은
모듈로 깊이를 유도함(아무 데나 깊이 안 팜).

---

## 4.7 재분석 — 에이전트 E (needs_reanalysis 전담)

`needs_reanalysis`는 C의 피드백 플래그고 그걸 처리하는 건 **E 하나뿐**임. A·B·C 누구도 이 상태의
finding을 건드리지 않아서 피드백이 아무도 안 보는 채로 남거나 둘이 동시에 손대는 일이 없음.

- 상태가 `needs_reanalysis`인 finding만 폴링함.
- C가 적은 정확한 관측과 재시도 이력을 읽고 빠진 전제나 실패한 재현 단계를 짚음.
- 해당 코드 경로를 다시 보고 해결에 필요한 **최소한의** 허가된 라이브 테스트만 해봄.
- 특히 빠뜨린 대체 진입점, 인증 상태 가정, 파서 차이, 환경 선행조건, 그리고 이걸 pre-auth나 인증된
  RCE로 바꿔줄 체인 고리를 찾음.
- 진짜 새 증거가 나오면 `candidate`나 `cross_validated`로 되돌려 C에게 넘기고 결정적인 라이브 증거가
  있으면 바로 `reproduced`로 올림. 반증되거나 재시도 상한을 소진했는데 새 증거가 없으면
  `false_positive`로 닫음.
- **그대로 되돌려 보내지 않음.** 바뀐 것 없이 튕기는 건 금지고 모든 갱신은 `write_finding.py`로만 함.
- 재분석 횟수는 `reanalysis_count`로 세고 `TF_MAX_REANALYSIS`(기본 3)를 넘기면 더 끌지 않음.

---

## 5. 상태 머신 (가설 → 증명 → 제품 판정)

모든 finding은 **가설**로 시작해서 증명 단계를 거침. `status` 필드가 곧 증명 강도임.

```
candidate                    한 분석가의 추론 (가장 약함)
   ↓ 교차검증
cross_validated              독립 엔진도 동의
   ↓ 라이브 재현
reproduced                   실제로 터뜨림 (PoC 있음) — 여기까진 '동작'만 증명
   ↓ 공식/벤더 제품경계 검토 + 증거 계약
confirmed                    제품 취약점으로 확정 (가장 강함)

   ✗ false_positive              반증됨 (보고서에서 제외)
   ✗ not_product_vulnerability   재현은 됐지만 문서화된 위험·의도된 동작·앱 설정·미지원 시나리오
   ↺ needs_reanalysis            판정 불가 → E가 전담
```

**왜 단계를 둠**: 정적 툴은 과탐하고(패턴 매치 ≠ 익스플로잇 가능) LLM은 흐름을 환각할 수 있음. 그래서
단계마다 증명 부담을 높이는 깔때기로 둘 다 거름. 재현이 동작에 대한 가장 결정적인 증거임. 그 동작이
벤더 제품의 결함인지는 공식 자료와의 대조가 결정함. 생산자가 매긴 심각도는 잠정치일 뿐이고 최종 랭킹은
재현 + 제품경계 판정이 지배함.

---

## 6. 동기화 — 다섯 세션이 어떻게 안 부딪히나

다섯 역할 세션의 장기 상태 조율은 전부 **파일시스템(`workspace/`)**으로 함. DB·브로커를 안 쓰는 이유는
인프라 부담과 휘발성임 — 세션이 재구성되면 메모리에 있던 문맥은 사라짐. 파일은 영속적이고 `ls`로
들여다볼 수 있음.

- **큐 = 디렉터리** — `workspace/findings/`에 finding 하나당 파일 하나. 파일 존재 = 큐에 있음,
  `status` = 진행 단계.
- **중복 제거 = 내용 기반 ID** — `id = sha1(track|vuln_class|sink.file|sink.line)`의 앞 16자. 같은 버그를
  두 번 찾으면 같은 ID라 같은 파일로 합쳐짐(멱등). sink에 쓸 만한 line이 없는 퇴화 케이스(매니페스트
  항목, 동적 디스패치)에만 `sink.symbol`을 섞어서 한 파일의 그런 finding이 전부 한 id로 뭉치는 걸 막음.
- **동시성 안전 = 파일락** — finding 쓰기 전에 `fcntl` 배타적 락. 여러 세션이 같은 파일을 써도 직렬화돼서
  안 깨짐. append-only라 남의 데이터를 덮지 않음.
- **상태별 소유권** — `needs_reanalysis`는 E, `confirmed` + 보고 가능 판정은 D, 나머지 흐름은 C. 같은
  finding을 둘이 동시에 밀지 않게 역할이 겹치지 않는 상태만 집음.
- **파생물은 매번 재생성** — `report.md`와 개별 보고서는 `findings/`에서 파생됨. 점진적으로 동기화하다
  어긋나게 두는 대신 대시보드가 매 사이클 통째로 다시 만듦. 진실의 원천은 항상 `findings/`.

---

## 7. 세션 생명주기 — 역할마다 supervisor 하나

에이전트 한 턴은 유한함. 스트리밍 소비자(C)와 피드백 담당(E)에겐 치명적임. 빈 큐를 보고 "완료"로
착각하고 끝나면 늦게 도착하는 finding을 아무도 재현하지 않음.

그래서 `audit.sh`는 루트 오케스트레이터를 두지 않고 **A/B/C/D/E 각각을 독립 프로세스로 띄운 뒤 역할마다
supervisor 루프를 하나씩 감쌈**:

- 역할 세션이 반환되면 5초 뒤 같은 역할을 같은 미션으로 다시 띄움(respawn)
- 매 세션 종료 후 `budget_guard.py --check`로 토큰 예산을 점검
- `MAX_HOURS`(기본 12시간)를 넘기거나 `workspace/_stop` 파일이 생기면 전부 멈춤
- 정지는 `touch workspace/_stop`을 **먼저** 한 뒤 `kill $(cat workspace/_pids)`. 순서가 바뀌면
  supervisor가 되살림
- 역할은 서브에이전트에 위임하지 않음. 미션 텍스트에 그렇게 박혀 있고 각 역할이 직접 읽고 직접 씀

환경변수로 조절하는 것들:

| 변수 | 역할 |
|---|---|
| `TF_BACKEND` | `claude` 또는 `codex`(기본). `claude`면 `TF_MODEL`(기본 `claude-opus-5`)로 전 역할 구동 |
| `CODEX_CMD`, `CODEX_CMD_A`...`CODEX_CMD_E` | 역할별 명령 덮어쓰기. 명시한 쪽이 항상 우선 |
| `MAX_HOURS` | supervisor 마감 시한 (기본 12) |
| `TF_REUSE_SEED=1` | 기존 시드를 검증하고 재사용. CODE_MODEL·HYPOTHESES의 타깃이 요청과 다르면 거부 |
| `TF_CANARY=1` | 라이브 URL이 없는 타깃(데스크톱/CLI)에도 out-of-band canary를 띄움 |
| `SSRF_HOST`, `SSRF_PORT` | canary 주소. 컨테이너 타깃이면 컨테이너가 해석할 수 있는 이름이어야 함 |
| `SPAWN_ONLY=1` | 띄워만 놓고 셸은 바로 반환 |
| `TAINTFORGE_EXTRA_CONTEXT` | 공통 미션 뒤에 붙는 타깃별 사실 |

canary 기동은 멱등임. 다른 세션이 이미 그 포트에서 듣고 있으면 그걸 재사용하지 서로 뺏지 않음.

`start.sh`는 여기에 tmux를 씌움. `taintforge` 세션에 runtime 창과 forge 창을 만들고 forge 창에
A/B/C/D/E 로그 패널 다섯 + 대시보드 한 개, 모두 여섯 패널이 뜸(여섯이 아니면 실패로 끝남). 패널 제목에
그 역할이 실제로 도는 모델명이 찍혀서 D에만 센 모델을 붙인 캠페인도 한눈에 보임. `TF_BACKEND=claude`일
때 로그는 stream-json JSONL이라 `.agents/stream_fmt.py`로 사람이 읽을 수 있게 렌더링함. 떼어내기는
`Ctrl-b` 다음 `d`, 다시 붙기는 `tmux attach -t taintforge`. tmux가 없으면 그냥 `audit.sh`로 넘김.

---

## 8. 실행 흐름 요약

```
1. SEED      ./seed.sh targets/<app> campaigns/<name>.modules   (결정론적, 체크아웃당 한 번)
2. LAUNCH    ./campaigns/<name>.sh → start.sh → audit.sh         (-u면 canary, URL 없으면 TF_CANARY=1)
3. PRODUCE   A(sink 역추적)·B(entry→자원)가 finding 스트림 생성    [candidate]
4. CONVERGE  C가 계속 루프:
               교차검증 → 재현(probe/canary/browser_probe)
               → 공식/벤더 제품경계 검토 → 증거 계약 → 공개 이력
               → poc.py 작성 → 보고서 생성
5. WEAPONIZE D가 confirmed + 보고 가능 판정 난 크리티컬만 체인·상승
6. FEEDBACK  판정 불가 → needs_reanalysis → E 전담 재분석
7. RESPAWN   역할 세션이 끝나면 5초 뒤 같은 역할을 다시 띄움 (MAX_HOURS까지)
8. STOP      touch workspace/_stop; kill $(cat workspace/_pids)
```

### 하네스 자체 점검

```bash
./test.sh
```

게이트가 TaintForge를 프롬프트가 아니라 하네스로 만들어주는 부분이라 그게 증명 가능하게 돌아가는지
확인함. `jsonschema`가 있는지(없으면 `write_finding.py`가 스키마 검증을 조용히 건너뜀), 두 스키마가
파싱되는지, `audit.sh`·`start.sh`·`seed.sh`·`campaigns/example.sh`의 셸 문법, 그리고
`.agents/skills/convergence/tests/test_*.py`(공식 검토 게이트와 증거 계약 테스트)를 한 번에 돌림.
게이트를 건드렸으면 이걸 돌리고 나서 손을 뗌.

### IDOR 확정 예시 (처음부터 끝까지)

1. **B**가 `자원컨트롤러::조회 → 자원::findById(id)`를 따라가다 경로에 소유권 체크가 없음을 발견.
   `defect_shape=missing_control`과 `missing_control{...}`을 채워 candidate 작성
2. **C**가 재현: alice·bob을 각자 jar에 로그인 → alice 세션으로 bob의 자원 요청 → 200 + bob 데이터 확인
   → `reproduced`
3. **C**가 벤더 문서·API 계약과 대조. 해당 엔드포인트가 소유자 범위를 보장한다고 쓰여 있는데 안 지켜짐
   → `official_review.verdict=product_vulnerability`, 공개 HTTPS 문서 URL을 `sources`에 기록
4. **C**가 증거 계약을 채움. `reachability`(어느 라우트, 최소 권한 '아무 인증 사용자', 호출 체인),
   `preconditions`(기본 설정 true), `primitive.escalation_ceiling`("타 사용자 객체 읽기까지, 쓰기는 미확인")
   → `confirmed`
5. **C**가 공개 이력 사다리를 돌림. 소스 이력·upstream 비교·이슈/PR·어드바이저리 전부 무소득이면
   `disclosure.status=novel` + `public_history` 기록
6. **C**가 requests 기반 `poc.py` 작성(alice 로그인 → bob 자원 GET → 유출 검증), `emit_poc.py`가
   `report/<id>/` 생성, `triage.py`가 **⚠️ Potential 0-day** 섹션에 올림

## 핵심 한 줄 요약

> **결정론적인 것은 툴로 한 번만, 판단은 집중된 역할 세션으로, 장기 상태는 영속적인 파일로 조율함.
> 모든 취약점은 가설로 시작해 재현으로 동작을 증명하고 공식/벤더 근거로 제품 취약점임을 확정함.**
