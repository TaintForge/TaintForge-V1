# TaintForge

**AI 에이전트 화이트박스 웹 보안 감사 파이프라인.** 특화된 역할 다섯을 하나의 코드베이스에
붙여놓고 사람 감사자가 하듯 일하게 한다. 코드를 읽고 데이터 흐름과 접근 제어를 따진 다음,
살아 있는 인스턴스에 실제로 요청을 쏴서 발견을 증명한다.

분석가는 모델이고 도구는 손이다. 파싱, SAST 힌트, 랭킹처럼 결정적인 작업은 스크립트가 맡는다.
애플리케이션 이해, 테인트 추론, 새니타이저 판정, 로직/IDOR 버그, PoC 작성처럼 판단이 필요한
일은 에이전트가 한다. 둘을 잇는 계약은 `schemas/finding.schema.json` 하나뿐이다.

백엔드는 둘 중 하나를 쓴다. `TF_BACKEND=codex`(기본) 아니면 `TF_BACKEND=claude`다. 모델은 `TF_MODEL`,
역할별로는 `CODEX_CMD_A` … `CODEX_CMD_E`로 덮어쓴다.

```
        ┌───────────────────────────────────────────────────────────────┐
        │  targets/<app>                          (read-only source)    │
        └───────────────────────────┬───────────────────────────────────┘
                                    │
        ┌───────────────────────────▼───────────────────────────────────┐
        │ SEED (no LLM)   ./seed.sh targets/<app> [modules-file]        │
        │   whole-repo structural index + per-module full models        │
        │   + coverage tree + hypotheses                                │
        │   → workspace/{CODE_MODEL.json, cm/*.json, coverage.json,     │
        │                HYPOTHESES.json}                               │
        └───────────────┬───────────────────────────┬───────────────────┘
                        │                           │
        ┌───────────────▼───────────┐   ┌───────────▼───────────────────┐
        │ A  PRODUCER               │   │ B  PRODUCER                   │
        │ defect_shape: flow        │   │ defect_shape: missing_control │
        │ sink → source, taint,     │   │ IDOR, authn/authz bypass,     │
        │ sanitizer judgment        │   │ business logic                │
        └───────────────┬───────────┘   └───────────┬───────────────────┘
                        │  write_finding.py (file-locked, append-only)  │
                        └───────────────┬───────────────────────────────┘
                                        ▼
        ┌───────────────────────────────────────────────────────────────┐
        │ C  CONVERGENCE        runs continuously while A & B produce   │
        │  cross_validate.sh → probe.py / canary.py / browser_probe.py  │
        │  → official_review → disclosure → poc.py → triage.py          │
        └───────┬───────────────────────────────────┬───────────────────┘
                │ needs_reanalysis                  │ confirmed + critical
                ▼                                   ▼
        ┌───────────────────────┐       ┌───────────────────────────────┐
        │ E  REANALYSIS         │       │ D  EXPLOITATION               │
        │ diagnose the failed   │       │ chain & escalate, defeat      │
        │ premise, re-test, and │       │ sanitizers, honest bounds     │
        │ hand it back to C     │       │ → exploit{} + exploit.py      │
        └───────────────────────┘       └───────────────┬───────────────┘
                                                        ▼
       workspace/report/report.md  +  report/<id>/{poc.py, finding.md, exploit.py}
```

## 동작 방식

`audit.sh`는 A/B/C/D/E를 각각 독립 프로세스로 띄우고 역할마다 감독 루프를 하나씩 붙인다.
루트 오케스트레이터는 없다. 세션이 일찍 끝나면 그 역할만 다시 살아난다. `MAX_HOURS`(기본 12)가
지나거나 `workspace/_stop`이 생기면 전부 내려간다. 다섯 역할은 `workspace/findings/`를
스트리밍 생산자-소비자 큐로 공유한다. `write_finding.py`가 파일 락을 걸고 append-only로 쓰는
덕에 동시 실행에도 큐가 깨지지 않는다.

- **A — producer, 주입 / 데이터 흐름.** SQLi, command/code injection, XSS, SSRF, path traversal,
  file inclusion, deserialization, XXE, SSTI, NoSQL, open redirect. 싱크를 먼저 잡고 파일을
  가로질러 공격자 입력까지 거꾸로 따라간 뒤 새니타이저를 판정한다. 결함 모양은 `flow`다.
- **B — producer, 로직 / 접근 제어.** IDOR/BOLA, 누락된 인가, 권한 상승, 인증·세션 우회,
  비즈니스 로직. 진입점에서 리소스까지 추적해 인증·역할·소유권 게이트가 그 경로 어딘가에
  실제로 있는지 본다. 결함 모양은 `missing_control`이다.
- **C — consumer, convergence.** 정적으로 교차검증하고 라이브 인스턴스에서 재현한 다음
  공식/벤더 제품 경계 검토를 거쳐 공개 이력을 조사한다. 그다음 취약점마다 실행 가능한
  `poc.py`를 쓰고 랭킹한다. A와 B가 일하는 동안 쉬지 않고 돈다.
- **D — exploitation.** C가 이미 증명하고 official_review 게이트를 통과시킨 치명적 발견만
  가져간다. 입증된 프리미티브에서 출발해 체이닝·권한 상승으로 실제 임팩트를 끝까지 민다.
  새니타이저·인용 처리가 막으면 무엇이 살아남는지 분석해 우회를 찾는다. 결과는 finding의
  `exploit` 객체와 독립 실행 가능한 `exploit.py`에 남는다.
- **E — reanalysis.** `needs_reanalysis` 상태를 전담한다. C의 재현 관찰 기록을 읽고 어떤
  전제가 틀렸는지, 어떤 증거가 빠졌는지 진단한 뒤 최소한의 승인된 라이브 테스트로 확인한다.
  새 증거가 생겼을 때만 C에게 돌려보내고 그렇지 않으면 `false_positive`로 닫는다. 아무것도
  바뀌지 않은 finding을 그대로 튕겨 보내지 않는다.

finding의 상태 전이:

```
candidate ──> cross_validated ──> reproduced ──> confirmed
                                       │              │
                        repro fails    │              └──> not_product_vulnerability
                                       ├──> false_positive
                                       └──> needs_reanalysis   (E owns it)
```

재현은 동작을 증명할 뿐 벤더의 제품 보안 경계를 넘었다는 증명이 아니다. `reproduced`에서
`confirmed`로 올라가려면 공식/벤더 1차 자료와의 비교가 반드시 끼어든다.

**넓게 훑지 말고 깊게 엮기.** 성숙한 코드에 남아 있는 진짜 버그는 눈에 띄는 싱크 하나가 아니라
개별로는 무해한 단계들의 *체인*인 경우가 많다. 여기 날 참조 하나, 저기 빠진 검사 하나, 끝에
도달 가능한 위험한 구문 하나가 합쳐져야 비로소 취약점이 된다. 연구자가 파서나
디시리얼라이저, 디스패처를 한 줄씩 읽으며 "공격자가 이 값을 쥐면 다음에 뭘 할 수 있지"를
매 단계 물어서 찾아내는 종류다. 에이전트가 한 번 훑고 끝내는 스캐너처럼 굴지 않고 그렇게
일하도록 딥 분석 노트북(`.agents/skills/_shared/leads.py`)을 뒀다.

`lead`는 아직 버그가 아닌 흥미로운 관찰이고(무엇을 `enables`하는지 같이 적는다), `primitive`는
확인된 능력이다. `note`는 한 타깃을 파고든 현재 상태다. 노트 덕에 재생성된 세션이 처음부터
다시 시작하지 않고 이어서 판다. `leads.py link`로 묶인 lead들은 후보 체인이 되고 C와 D가 그걸
하나의 연쇄 취약점으로 실현하려 시도한다. coverage는 파서, 디시리얼라이저, 디스패처,
템플릿·리플렉션 코드처럼 체인이 숨는 모듈을 먼저 내준다. lead는 그 자체로 finding이 못 된다.
그렇다고 아직 버그가 못 됐다는 이유로 버리지도 않는다. 다른 세션이 찾던 마지막 조각일 수 있다.

## 모든 역할을 묶는 방법론

`.agents/skills/_shared/METHODOLOGY.md`는 각 역할이 `AGENTS.md` 다음, 자기 스킬보다 먼저 읽는
클래스·언어 무관 계약이다. 싱크 우선 스캐너만으로는 틀리는 지점 네 가지를 못 박는다.

- **모양은 하나가 아니라 둘.** 결함은 위험한 흐름(`defect_shape: "flow"`) 아니면 누락된
  통제(`defect_shape: "missing_control"`)다. 트랙 A와 B는 취약점 클래스 대신 이 두 모양을
  따라 이름 붙었다. 그래서 crypto, DoS, 정보 노출, 설정 오류, 공급망, 메모리 안전성, TOCTOU
  버그에도 항상 주인이 있고 두 트랙 사이로 새지 않는다.
- **source는 요청 입력만이 아니다.** 공격자 영향은 여덟 갈래다. 직접 입력, 신원·인가 상태,
  2차/저장된 값, 해제 후 초기화되지 않은 상태, bailout으로 고아가 된 상태, 요청·워커를 넘나드는
  상태, 초기화되지 않은 재사용, 그리고 시간과 순서. 이 중 4번부터 7번은 테인트 엔진에도
  structural 콜 그래프에도 보이지 않고 수명과 에러 경로를 직접 읽어야만 나온다.
- **필수 패스 일곱.** 진입점 × 권한 맵, 가드 감사, 불변식 스윕, 장수명 객체 수명 스윕,
  일곱 싱크 그룹 *전부*로의 테인트, 에러·예외 경로 차분, 교차 스코프·동시성 토폴로지.
  마지막 셋은 의도적으로 도구 지원이 없다. 코드를 직접 읽는 패스고 스캐너가 흘린 버그가 바로
  거기 산다.
- **정직한 한계, 강제.** `write_finding.py`는 모양, 도달 가능성(진입점 + 최소 권한 + pre-auth를
  콜 체인으로 입증), 전제조건(기본 설정인지 명시된 비기본 설정인지), 입증된 권한 상승 상한이
  없으면 finding을 `confirmed`로 올려주지 않는다. 새니타이저나 패치된 빌드에서만 관찰된 것은
  `repro.stock_replay`가 스톡 빌드 실행을 기록하기 전까지 lead로 남는다.

## 레이아웃

```
taintforge/                         <- repo root (run from here)
  AGENTS.md                         <- the operating contract every role reads first
  seed.sh                           <- ./seed.sh targets/<app> [modules-file]
  audit.sh                          <- seed + five supervised role sessions (A/B/C/D/E)
  start.sh                          <- tmux launcher: one pane per role + dashboard
  test.sh                           <- harness self-tests (the gates must stay provably working)
  accounts.json[.example]           <- test accounts for dynamic auth/IDOR testing
  campaigns/
    README.md                       <- what a campaign is; the committed contract
    example.sh / example.modules    <- copy these; your own campaigns stay untracked
  schemas/
    code_model.schema.json
    finding.schema.json             <- one finding; the contract that glues the roles
  .codex/
    config.toml                     <- codex project settings
    agents/*.toml                   <- A/B/C/D/E role definitions (codex backend)
  .agents/
    stream_fmt.py                   <- renders the claude backend's stream-json into a pane
    refs/pentesting-web/            <- technique reference notes the A/B skills cite
    skills/
      _shared/      METHODOLOGY.md, write_finding.py, leads.py, budget_guard.py
      source-model/ build_code_model.{sh,py}, ts_extract.py, callgraph.py,
                    coverage.py, proof_ledger.py
      hypothesize/  gen_hypotheses.py, catalog.json, cwe_to_hypotheses.py
      vuln-track-a/ run_semgrep.sh, fetch_rules.sh, semgrep_to_hints.py, rules/
      vuln-track-b/ build_authz_matrix.py
      convergence/  cross_validate.sh, correlate.py, probe.py, canary.py, browser_probe.py,
                    official_review.py, triage.py, emit_poc.py, queue.py, dashboard.py
      convergence/tests/ test_evidence_contract.py, test_official_review_gate.py
  targets/<app>                     <- code under assessment (read-only)
  workspace/
    CODE_MODEL.json                 <- whole-repo structural + comprehension
    cm/<module>.json                <- per-module full models (dataflow + sinks + proof ledger)
    coverage.json                   <- directory -> module -> entry point tree + progress
    HYPOTHESES.json                 <- business-logic hypotheses bound to entry points
    leads.json                      <- leads, primitives, candidate chains
    _analysis_notes.json            <- per-target running dig notes (survive respawns)
    hints/                          <- optional tool leads (never findings)
    findings/<id>.json              <- the shared queue
    report/report.md                <- the ranked index
    report/<id>/poc.py              <- per-vuln runnable PoC
    report/<id>/finding.md          <- per-vuln individual report
    report/<id>/exploit.py          <- per-vuln weaponized exploit (agent D)
    _accounts.json                  <- copied test accounts
    _authz_matrix.json  _canary.log
    _log_{A,B,C,D,E}.txt  _log_canary.txt
    _pids  _runner.sh  _stop
```

`workspace/`는 지속 메모리다. 세션이 재생성돼도 coverage, leads, findings를 잃지 않고 이어간다.

## Code Model

`source-model`이 `workspace/CODE_MODEL.json`을 한 번 만들고 나머지 전부가 재사용한다.

- **`structural`**(도구가 채운다): 파일, 진입점, 그리고 **콜 그래프**(`caller -> callee` 엣지). 여기에
  `query`/`exec`/`system`/`unserialize`/`include`/`require`/`eval`/`file_get_contents` 같은
  위험한 빌트인 호출 지점이 `<builtin-sink>`로 태깅된다. 에이전트가 파일을 가로질러 흐름을
  따라갈 수 있게 해주는 게 이 그래프다.
- **`comprehension`**(에이전트가 채운다): `service_identity`, `route_map`, `feature_flows`,
  `permission_model`, `user_journeys`, `trust_boundaries`. 트랙 B의 로직 버그 사냥이 여기에
  의존한다.

추출기는 tree-sitter 기반(`ts_extract.py`)이고 Python은 `ast`, 파서를 못 구한 언어는 정규식으로
떨어진다. tree-sitter 경로를 쓰는 건 `call_user_func($x)`, `obj[key]()`, `getattr(o,n)()` 같은
동적 디스패치를 `sink_category="dynamic-call"`로 뽑아내려는 것이다.
`TF_NO_TREESITTER=1`로 끄면 정규식 경로만 남는다.

분석 대상 파일이 `TF_GRAPH_ONLY_FILES`(기본 4000)를 넘으면 빌드가 자동으로 graph-only로
내려간다. graph-only 모델에는 dataflow도, 싱크 집합도, proof ledger도 없는데 그게 A와 B가 실제로
질의하는 내용 대부분이다. 그래서 큰 타깃은 보안 경계를 지고 있는 영역마다 `workspace/cm/<name>.json`에
자기 full model을 따로 갖는다. `seed.sh`에 modules 파일을 넘기면 만들어진다.

취약점은 한 줄이 아니라 **파일을 가로지르는 흐름** 위에 산다. 두 트랙 모두 콜 그래프를 지도로
쓰고 `callgraph.py`로 질의한다.

```bash
python3 .agents/skills/source-model/scripts/callgraph.py --stats            # edge/sink counts
python3 .agents/skills/source-model/scripts/callgraph.py --callers <sink>   # who calls query/unserialize/include/...
python3 .agents/skills/source-model/scripts/callgraph.py --callees <file>   # what a handler calls
python3 .agents/skills/source-model/scripts/callgraph.py --trace   <sink>   # backward paths into a sink

# per-module full models (large targets)
python3 .agents/skills/source-model/scripts/callgraph.py    --model  workspace/cm/<name>.json --sinks
python3 .agents/skills/source-model/scripts/proof_ledger.py --ledger workspace/cm/<name>.proof_ledger.json --next route
```

트랙 A는 싱크에 닻을 내리고 공격자 입력까지 **거꾸로** 따라간다. 트랙 B는 진입점에서 리소스
접근까지 **앞으로** 따라가며 경로 어딘가에 인가·소유권 게이트가 있는지 본다. 소유권 검사 없이
도달 가능한 리소스 로드는 IDOR다. 그래프는 거칠다. 입력에 직접 쓰이는 구문 싱크(`include $_GET[...]`,
요청 값을 그대로 넘긴 `eval`)는 엣지로 잡히지 않으므로 에이전트는 코드도 읽는다. 큰 앱이라면
`call_edges`가 수천 단위여야 하고 `0`이면 structural 빌드가 실패한 것이다.

`coverage.py`는 큰 코드베이스를 평평한 목록 대신 **디렉터리 → 모듈 → 진입점 트리**로
모델링한다(vendor/tests 제외, 큰 디렉터리는 `TF_SPLIT_THRESHOLD`(기본 120)와
`TF_MAX_DEPTH`(기본 4)로 분할). 모듈마다 Code Model에서 끌어온 **진입점**(라우트/핸들러)이
붙으므로 coverage는 디스크 위의 파일이 아니라 *도달 가능한 공격 표면*을 추적한다.
`--next`는 라우트를 노출하는 모듈을 리프 라이브러리보다 먼저 내주고 `--tree`는 노드별 상태와
함께 트리를 찍는다. `--summary`는 진입점 표면이 얼마나 분석됐는지 따로 보고한다. 그래서 여기서
"커버리지 100%"는 "모든 파일을 훑었다"가 아니라 "도달 가능한 모든 라우트를 안쪽으로 따라갔다"를
뜻한다.

## 캠페인

캠페인은 평가 대상 하나를 가리킨다. 어떤 체크아웃인지, 라이브 URL과 계정은 무엇인지, 어떤
모듈이 full model을 받는지, 그 코드베이스에서 역할들이 알아야 할 사실이 무엇인지. 전부
하네스가 아니라 설정이라서 `campaigns/README.md`와 `example.*` 한 쌍만 git에 들어간다.
나머지는 `.gitignore`가 `campaigns/*`를 막아 로컬에 남는다.

캠페인은 파일 두 개다.

| 파일 | 내용 |
|---|---|
| `<name>.modules` | 한 줄에 `name:path` 하나. 각 항목이 `workspace/cm/<name>.json`에 full model을 하나씩 받는다. `#` 주석과 빈 줄은 무시된다. |
| `<name>.sh` | 환경변수(타깃, URL, 계정, 백엔드, 모델, 카나리) + `TAINTFORGE_EXTRA_CONTEXT`, 그리고 `exec ./start.sh ...`. |

```bash
./seed.sh targets/<app> campaigns/<name>.modules   # once per checkout
./campaigns/<name>.sh                              # run the roles
```

`TAINTFORGE_EXTRA_CONTEXT`에는 역할들이 싸게 알아낼 수 없는 타깃별 사실만 넣는다. 분석 중인
정확한 태그/커밋, 라이브 인스턴스의 모양(로그인 라우트, nonce/CSRF 방식, 계정별 권한), 이
스택에서 추출기가 못 보는 것(PHP라면 `add_action`/`apply_filters` 훅 디스패치, 가변 함수,
`call_user_func`), 이 벤더의 공개 사다리가 실제로 어디 있는지. 방법론을 다시 설명하기 시작한
캠페인은 설정이기를 그만둔 것이다.

## 설치

```bash
cd <repo>
python3 -m venv .venv && . .venv/bin/activate
pip install -r .agents/skills/source-model/scripts/requirements.txt
# browser_probe.py (XSS execution proof), optional:
pip install playwright && python3 -m playwright install chromium
# OpenGrep (preferred SAST engine):
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
export PATH="$HOME/.opengrep/cli/latest:$PATH"
# vendor community rules (once, online):
.agents/skills/vuln-track-a/scripts/fetch_rules.sh
chmod +x seed.sh audit.sh start.sh test.sh .agents/skills/*/scripts/*.{sh,py}
./test.sh
```

`jsonschema`가 없으면 `write_finding.py`가 스키마 검증을 조용히 건너뛴다. 그래서 `test.sh`는
그것부터 확인한다.

## 실행

먼저 시드를 만든다. 작은 타깃이면 modules 파일 없이도 된다.

```bash
./seed.sh targets/<app>                            # small target
./seed.sh targets/<app> campaigns/<name>.modules   # large target: per-module full models
```

모듈 모델은 `TF_SEED_JOBS`(기본 6)개씩 병렬로 빌드된다. 이번 버전에 없는 경로는 건너뛰므로
modules 파일 하나가 릴리스를 넘어 계속 쓰인다.

그다음 역할을 띄운다.

```bash
./start.sh -u http://localhost:8080 targets/<app>     # tmux: 5 role panes + dashboard
./start.sh targets/<app>                              # static only, still with the dashboard
```

`start.sh`는 tmux 세션 `taintforge`를 열고 `forge` 윈도에 A/B/C/D/E 로그 패널 다섯과 대시보드
패널 하나를 띄운다(역할별로 실제 돌고 있는 모델 이름이 패널 제목에 찍힌다). 대시보드는 coverage 바, 상태·클래스별
finding 수, potential 0-day와 무기화 카운터, 최근 히트, 경과 시간을 보여준다. 떼어내려면
`Ctrl-b` 다음 `d`, 다시 붙으려면 `tmux attach -t taintforge`. 전부 멈추려면
`touch workspace/_stop; kill $(cat workspace/_pids); tmux kill-session -t taintforge`.
tmux가 없으면 `start.sh`는 그대로 `audit.sh`로 넘어간다.

tmux 없이 돌릴 때(로그는 `workspace/_log_{A,B,C,D,E}.txt`):

```bash
./audit.sh -u http://localhost:8080 targets/<app>
./audit.sh --url http://host --accounts creds.json targets/<app>
TF_CANARY=1 ./audit.sh targets/<app>    # no live URL, but the local lab copy needs an OOB oracle
```

타깃이 **어딘가에서 돌고 있을 때** `-u/--url`을 준다. 그러면 역할들이 실제 요청으로 발견을
동적으로 확인한다. 테스트 계정은 리포지터리 루트의 `accounts.json`(또는 `--accounts <file>`)에
`{username, password}` 배열로 넣는다(`accounts.json.example` 참고). 로그인·세션 흐름은 에이전트가
코드에서 직접 알아낸다. IDOR/인가는 한 사용자의 요청을 다른 사용자의 세션으로 재생해 증명한다.
`--url`이 없으면 라이브 서버가 필요한 발견은 추측하는 대신 한계를 그대로 기록한다. 계정은
`workspace/_accounts.json`으로 복사되며 요청은 넘겨준 URL로만 나간다.

URL은 없지만 로컬 랩에 빌드한 사본이 out-of-band 오라클을 필요로 할 때 `TF_CANARY=1`을 준다.
그러면 `audit.sh`가 카나리를 직접 띄우고 직접 내린다. 캠페인 스크립트가 리스너를 손으로
만들다가 `audit.sh`가 정리하는 것과 어긋나는 일을 막는다.

주요 환경변수:

| 변수 | 기본값 | 하는 일 |
|---|---|---|
| `TF_BACKEND` | `codex` | `codex` 또는 `claude`. `claude`면 다섯 역할 모두 `claude -p --output-format stream-json`으로 돈다 |
| `TF_MODEL` | `claude-opus-5` | `TF_BACKEND=claude`에서 쓰는 모델 |
| `MAX_HOURS` | `12` | 감독 루프가 도는 최대 시간 |
| `TF_REUSE_SEED` | `0` | `1`이면 기존 CODE_MODEL/coverage/HYPOTHESES를 타깃 일치까지 검증하고 재사용한다 |
| `TF_CANARY` | `0` | `--url` 없이도 out-of-band 카나리를 띄운다 |
| `SSRF_HOST` / `SSRF_PORT` | `127.0.0.1` / `9111` | 카나리가 바인딩할 호스트·포트 |
| `SPAWN_ONLY` | `0` | `1`이면 감독 프로세스만 띄우고 바로 빠진다 |
| `TF_TOKEN_BUDGET` | `0` | 0이 아니면 누적 토큰 초과 시 `budget_guard.py`가 `workspace/_stop`을 만든다 |
| `TAINTFORGE_EXTRA_CONTEXT` | — | 역할 프롬프트 뒤에 붙는 타깃별 메모 |
| `CODEX_CMD`, `CODEX_CMD_A` … `CODEX_CMD_E` | — | 역할별 실행 명령 전체를 덮어쓴다 |

codex 백엔드의 기본 명령은 `--sandbox workspace-write`로 돈다. `workspace/`에는 쓰고 `targets/`는
읽기 전용이다. 역할 다섯이 동시에 추론하므로 단일 에이전트보다 토큰을 많이 먹는다.

### 진행 상황 보기

`start.sh`를 쓰면 대시보드 패널이 실시간으로 보여준다. 헤드리스라면 다른 셸에서:

```bash
tail -f workspace/_log_C.txt                                   # convergence stream
python3 .agents/skills/convergence/scripts/queue.py --counts   # queue by status
python3 .agents/skills/source-model/scripts/coverage.py --summary
ls workspace/findings | wc -l
```

`TF_BACKEND=claude`의 로그는 stream-json JSONL이다. 사람이 읽으려면
`tail -n +1 -F workspace/_log_C.txt | python3 -u .agents/stream_fmt.py`로 통과시킨다.

## 동적 재현 (라이브 타깃)

`-u/--url`을 넘기면 convergence 세션이 돌고 있는 앱에 대고 발견을 증명한다.

- **`probe.py`**는 세션을 안다. `--jar FILE`이 호출 사이에 쿠키를 유지하므로 로그인한 뒤
  그 세션으로 보호된 리소스를 때릴 수 있다(로그인 라우트·CSRF·쿠키 형식은 코드에서 직접
  알아낸다). `-X`, `-H`, `-d`, `--timeout`을 받고 `--no-redirect`는 `Location`을 드러낸다.
  JSON 결과에 `status`, `set_cookie`, `cookies`, 타이밍, 본문 일부가 실린다.
- **IDOR/인가**는 **두 신원**을 재생해 증명한다. alice와 bob을 각각 다른 jar로 로그인시키고
  alice의 jar로 bob의 객체를 요청한다. bob의 데이터가 담긴 `200`이면 확정이다. 이걸 하려면
  `accounts.json`에 일반 계정이 2개 이상 있어야 한다(admin 하나로는 교차 사용자 접근을 증명하지
  못한다).
- **XSS**는 반사가 아니라 **실행**으로 증명한다. `browser_probe.py`가 헤드리스 Chromium
  (Playwright)에서 페이로드 URL을 열고 다이얼로그가 뜨거나 주입된 마커가 실행됐을 때만
  `executed:true`를 보고한다. 저장형·인증 필요 XSS는 `--jar`로 세션을 주입한다.
- **SSRF / 블라인드**는 **`canary.py`** 를 쓴다. `--url`이나 `TF_CANARY=1`이면 out-of-band HTTP
  리스너가 `127.0.0.1:9111`(기본)에 자동으로 뜬다. 타깃이 `http://<canary>/<token>`을 가져오게
  만든 다음 `canary.py check <token>`을 돌려 HIT가 나오면 SSRF가 증명된다. 콜백이 없는
  내부·블라인드 SSRF는 내부 호스트를 대상으로 한 응답·타이밍 차이로 판정한다.

재현은 항상 **PoC**로 남긴다. 재현되는 정확한 요청은 `repro.poc`에, 결정적 증거는
`repro.response`에 넣는다. 재현이 애매하면 `candidate`에 방치하지 않고 `needs_reanalysis`로
넘겨 E가 집어가게 한다.

## 확인 게이트: official_review와 disclosure

동작하는 PoC는 동작을 증명할 뿐 제품 취약점을 증명하지 않는다. 그래서 `reproduced` 다음에
**공식/벤더 제품 경계 검토**가 의무로 들어간다. 재현된 정확한 동작, 컴포넌트와 버전,
전제조건, 기본·지원 설정, 문서화된 보안 경계, 싱크 소유권을 1차 자료와 비교한다. 공식 문서와
보안 가이드, API 계약, 기본 템플릿·샘플, 버전이 박힌 소스 주석·테스트, 어드바이저리, 릴리스
노트, 패치, 벤더 소유 이슈·디스커션이 여기 해당한다.

- `product_vulnerability` 또는 `known_vulnerability` → `confirmed`
- `documented_hazard`, `expected_behavior`, `application_misconfiguration`,
  `unsupported_scenario` → `not_product_vulnerability`
- `inconclusive` → `reproduced` 유지. 잠재 0-day로 랭킹되지 않고 D에게도 가지 않는다.

`write_finding.py`가 터미널 상태를 실제로 막는다.

- `confirmed`와 `not_product_vulnerability`는 `official_review{checked,verdict,sources,rationale}`에
  `product_version`과 `default_configuration` 판단, 그리고 공개 HTTPS 1차 자료 URL이 최소 하나
  있어야 통과한다. GitHub의 `/blob/`, `/tree/`, `/raw/` 링크는 보조 증거일 뿐 이 게이트를 혼자
  통과시키지 못한다.
- `confirmed`는 증거 계약도 함께 본다. `defect_shape`,
  `reachability{entry_point,min_privilege,pre_auth}`, `preconditions.default_configuration`
  (`false`면 `required_settings`에 정확한 비기본 설정), `primitive.escalation_ceiling`.
  `repro.instrumentation_only`가 `true`면 `repro.stock_replay`에 스톡 빌드 실행 결과가 있어야 한다.
- `disclosure.status=novel`은 `disclosure.public_history` 전체를 요구한다. `upstream_repository`,
  정확한 패치 지문 `exact_anchors` 2개 이상, `source_history`, `vendor_issues_prs`,
  `advisories_releases`, 그리고 테스트한 태그와 upstream main·지원 릴리스 브랜치의 비교
  `head_or_release_comparison`. 공개 이슈, PR, 커밋, 패치, 회귀 테스트가 하나라도 맞으면 CVE나
  보안 라벨이 없어도 `known`이다. 증거가 모자라면 `inconclusive`이고 트라이에이지에 잠재 0-day로
  뜨지 않는다.
- `exploit` 객체는 `confirmed` + 보고 가능한 official_review 판정 없이는 쓰이지 않는다.

`triage.py`가 `workspace/report/report.md`에 랭킹된 인덱스를 쓴다. `Potential 0-day` 섹션은 공식
검토를 통과한 제품 취약점에만 열린다. `Official/vendor review pending`과
`Public-history/disclosure review pending` 섹션이 아직 게이트를 못 넘은 항목을 따로 보여준다.
대시보드가 몇 초마다 리포트와 조건을 만족한 취약점별 폴더를 다시 생성하므로 내용이 묵지 않는다.

## 취약점별 PoC와 리포트

확인 게이트를 통과한 발견마다 에이전트가 그 버그에 맞춘 `poc.py`를 쓴다(`requests` 사용, pre-auth
버그에는 로그인 단계가 없고 다단계 흐름에는 필요한 만큼 요청이 들어가며 PASS/FAIL을 찍는다).
전체 소스는 `repro.poc_script`에 저장되고 `emit_poc.py`가 취약점당 폴더 하나로 떨군다.

```
workspace/report/<id>/poc.py        # standalone, re-run with: python3 poc.py
workspace/report/<id>/finding.md    # that vuln's individual report
workspace/report/<id>/exploit.py    # agent D's weaponized exploit, when one exists
```

취약점별 리포트는 절대 합치지 않는다. `report.md`는 랭킹된 인덱스로 남는다.

## 무기화 (D)

코드 실행으로 끝날 수 있는 확정 발견이라면 D는 PoC를 넘어선다. 입증된 프리미티브에서 출발해
실제로 도달 가능한 최대 임팩트까지 체이닝·상승시킨다. 새니타이저나 이스케이프·인용 처리가
뻔한 페이로드를 막으면 정확히 무엇이 살아남는지 분석해 동작하는 우회를 찾는다. 모든 단계는
승인된 랩 타깃에서 검증한다.

결과는 finding의 **`exploit`** 객체에 들어간다.
`{depth: shallow|chained|weaponized, primitive, max_impact, steps, mitigations_bypassed,
constraints, oob_evidence}`. 그리고 C의 `poc.py`와 별개로
`workspace/report/<id>/exploit.py`가 떨어진다. D는 **정직한 한계**를 적는다. 임팩트가
제한적이면(예: 인자 없는 단일 토큰 명령만 실행된다면) 부풀리지 않고 그대로 정확히 쓴다.
D와 그 산출물은 본인 소유이거나 테스트 권한을 받은 자산에만 쓴다. 가리켜주지 않은 호스트는
건드리지 않는다.

## 도구 (힌트와 교차검증 전용, finding의 저자가 아님)

- **tree-sitter + ast + 정규식 추출기** — Code Model의 심볼·콜 그래프 추출. Python은 `ast`,
  나머지는 tree-sitter, 파서가 없으면 정규식으로 떨어진다.
- **OpenGrep / Semgrep** — 트랙 A 리드와 트랙 A 스타일 교차검증. OpenGrep을 권한다. 비공개
  코드에 무료고 교차 파일 테인트가 살아 있으며 코어가 더 안정적이다(Semgrep OSS는 아주 큰
  리포에서 segfault를 낸다). 리드는 `workspace/hints/`로 가고 절대 바로 finding이 되지 않는다.
- **CodeQL** — convergence의 기본 교차검증 엔진. C/C++/C#/Go/Java/JS/TS/Python/Ruby/Swift/Rust를
  지원하지만 **PHP는 지원하지 않는다**. `cross_validate.sh`는 CodeQL이 없거나 실패하면 OpenGrep으로
  떨어지므로 PHP 타깃은 자연히 OpenGrep을 쓴다. CodeQL은 OSI 오픈소스·연구 용도에만 무료고
  비공개 코드에는 GitHub Advanced Security가 필요하다.
- **probe.py / canary.py / browser_probe.py** — 동적 재현(HTTP 세션, out-of-band SSRF, 헤드리스
  브라우저 XSS 실행 증명).
- **leads.py** — 딥 분석 노트북. `write_finding.py`처럼 파일 락이 걸려 있다.

쓰기 전에 도구가 있는지 확인하고 없으면 없다고 말한 뒤 있는 것으로 진행한다.

## 자체 테스트

```bash
./test.sh
```

`write_finding.py`, `proof_ledger.py`, `triage.py`의 게이트가 TaintForge를 프롬프트가 아닌
하네스로 만든다. 그래서 그 게이트가 증명 가능하게 동작하는 상태로 남아야 한다. `test.sh`는
`jsonschema` 존재 여부와 두 스키마의 파싱, `audit.sh`/`start.sh`/`seed.sh`/`campaigns/example.sh`의
셸 문법, 그리고 `.agents/skills/convergence/tests/`의 게이트 테스트를 돌린다. 저 셋 중 하나라도
건드렸다면 실행한다.

## 설계 원칙

- **에이전트가 찾고 도구는 거든다.** 모든 finding은 모델이 `write_finding.py`를 통해 쓴다.
  OpenGrep/Semgrep/CodeQL은 리드나 교차검증만 건넨다. SAST 히트는 들여다볼 자리지 finding이 아니다.
- **모델 구축과 사냥을 분리한다.** `source-model`이 재사용 가능한 사실을 한 번 만들고 두 트랙이
  그 위에서 판단한다.
- **흐름을 안다.** 유한한 싱크 집합에 닻을 내리고 콜 그래프로 파일을 가로질러 거꾸로 추론한다.
  자기 파일 안에서는 안전한 싱크가 몇 단계 떨어진 호출에서 오염된 입력을 받는 일이 흔하다.
  트랙 B는 진입점에서 리소스 접근까지의 경로에 같은 일을 한다.
- **스트리밍, 병렬, 자율.** A와 B가 동시에 생산하고 C가 실시간으로 소비하며 E가 피드백을
  해소하고 D가 확정된 치명적 발견을 끝까지 민다. 역할마다 감독 루프가 붙어 각자 계속 돈다.
- **빠짐없이.** 모든 모듈, 모든 싱크와 라우트마다 버그를 찾거나 왜 안전한지 근거를 남긴다.
- **재현이 가장 강한 증거, 다만 전부는 아니다.** 라이브로 쏴서 성공해야 `reproduced`가 되고
  공식/벤더 검토까지 통과해야 `confirmed`가 된다. 실패는 재분석으로 되돌아간다.
- **append-only, 파일 락.** 안정적인 id와 `history`를 갖춘 finding이라 역할 다섯이 동시에 써도
  안전하고 전부 감사 가능하다.

더 자세한 컴포넌트·워크플로 설명은 `docs/DOCS.md`에 있다. 다만 그 문서는 아직 다섯 역할 러너로
갱신되지 않았고 루트 오케스트레이터와 서브에이전트 넷을 전제로 쓰여 있으니 구조 설명은 이
README와 `AGENTS.md`를 기준으로 본다.
