# TaintForge — 상세 문서

이 문서는 구성 요소와 워크플로를 하나씩 깊게 설명한다. 빠른 시작은 [README.md](../README.md)를 본다.
TaintForge는 **웹 애플리케이션과 웹에 노출된 서비스**의 소스를 읽어 평가하는 하네스다.

문서 전체에서 쓰는 용어:

- **역할 세션(role session)** — `audit.sh`가 띄우는 독립 프로세스 하나. A/B/C/D/E 다섯 개가 각자
  자기 supervisor 루프 안에서 돌고 일찍 끝나면 다시 띄워진다.
- **프로듀서** — 파인딩을 *만드는* 역할(A, B).
- **컨슈머** — 큐를 *검증·재현·판정·보고*하는 convergence 역할(C).
- **파인딩(finding)** — 후보 취약점 하나. `workspace/findings/<id>.json`으로 저장되고
  `schemas/finding.schema.json`을 따른다. 이 JSON 계약이 시스템의 등뼈다.
- **방법론(METHODOLOGY)** — `.agents/skills/_shared/METHODOLOGY.md`. 언어·타깃·클래스와 무관한
  결함 사냥 계약이고 다섯 역할 전부가 여기에 묶인다.
- **시드(seed)** — LLM을 쓰지 않는 결정적 전처리. Code Model, per-module 모델, coverage 트리,
  `HYPOTHESES.json`을 만든다.
- **캠페인(campaign)** — 타깃 하나분의 설정 묶음. `campaigns/<name>.sh` + `campaigns/<name>.modules`.

---

## 1. 아키텍처 한 문단

TaintForge는 먼저 타깃의 구조 모델을 시드한다(ast+regex 호출 그래프, 모듈 분할, proof ledger,
가설). 그다음 `audit.sh`가 **다섯 개의 독립 역할 세션을 동시에** 띄운다. 프로듀서는 둘이다. A는
injection / data-flow 결함을, B는 logic / access-control 결함을 사냥해서 file-lock이 걸린 공용 큐
`workspace/findings/`로 흘려보낸다. C(convergence)는 그 큐를 쉬지 않고 소비한다. 독립 엔진으로
교차 검증한 뒤 살아 있는 인스턴스에 재현하고 벤더 1차 자료와 대조해 제품 취약점인지 판정한다.
그다음 공개 이력을 훑어 `known`인지 `novel`인지 가른다. 마지막으로 돌아가는 PoC를 쓰고 전부
순위를 매겨 리포트로 만든다. D(exploitation)는 C가 이미 `confirmed`까지 끌고 간 critical 클래스만 받아 무기화한다 —
체이닝, 임팩트 상승, 새니타이저 우회를 정직한 한계와 함께 기록한다. E(reanalysis)는
`needs_reanalysis`를 전담해서 무엇이 빠졌는지 진단하고 새 증거가 붙은 것만 C로 되돌린다.
다섯 역할 모두 셸 supervisor 루프 하나씩을 달고 있어서 세션이 일찍 끝나면 `MAX_HOURS`나
`workspace/_stop`까지 계속 재시작된다. 도구는 리드와 교차 확인만 준다. 파인딩을 쓰는 분석가는
언제나 역할 세션 쪽이다.

평가의 1차 목표는 **pre-authentication RCE**를 실제로 보여주는 것이고 그다음이 authenticated
RCE다. 임팩트가 낮은 결함은 RCE 체인의 믿을 만한 연결 고리가 될 때 주로 의미를 갖는다.

---

## 1.5 왜 이렇게 쪼갰나 — 경계와 동기화

여기는 아키텍처의 "왜"다. 작업을 왜 하필 이 단위로 잘랐고 독립 프로세스들이 서로 밟지 않으면서
어떻게 일관성을 유지하는지. 돌리기만 할 게 아니라 설계를 고칠 생각이면 이 절을 읽는다.

### 1.5.1 애초에 왜 나누나 (관심사 분리)

**시드(LLM 없음) vs 사냥(LLM).** 호출 그래프, 모듈 목록, built-in sink 엣지는 *결정적*이다. PHP를
파싱해 호출 그래프를 만드는 데 판단이 들어갈 자리는 없다. 그래서 그 일은 ast+regex 추출기가 *한
번만* 싸게 해치우고 `CODE_MODEL.json`에 써두면 모두가 읽는다. 세션마다 구조를 다시 유도하면 같은
사실을 다섯 번 재계산하느라 LLM 토큰과 벽시계 시간을 쓰고 다섯 벌의 사본이 서로 어긋날 수도
있다. 결정적 사실은 한 번 만들어 공유하고 판단에 모델을 쓴다.

**찾는 쪽 vs 증명하는 쪽(프로듀서/컨슈머).** 찾기와 증명하기는 비용 구조가 다른 별개의 일이다.
찾기는 넓게 훑는 쪽이라 비교적 싸다. 코드를 읽고 추론해서 후보를 적으면 끝난다. 증명하기는 깊게
파는 쪽이라 비싸다. 라이브 요청을 띄워 로그인하고 리플레이한 뒤 페이로드를 쏘고 벤더 문서를 뒤져
PoC까지 쓴다. 한 세션이 둘 다 하면 비싼 재현이 끝날 때까지 다음 모듈 스캔이 멈춘다. 쪼개 두면 A와
B가 코드베이스를 계속 쓸어나가는 동안 C는 병렬로 재현을 갈아낸다. 덤으로 재현 작업이 "찾는 김에
대충"이 아니라 자기 프롬프트를 따로 갖는다.

**A vs B (flow vs 부재).** 둘은 *반대 방향*의 방법과 *다른 시드*를 쓴다. 프롬프트 하나로 둘 다
하면 둘 다 어설프게 된다.

- **A(flow 트랙)** 는 *sink-first*다. 위험한 연산에서 출발해 호출 그래프를 **거꾸로** 걸어 소스까지
  가고 중간의 새니타이저를 판정한다. 패턴이 문법적이라 OpenGrep 같은 도구가 거들 수 있다.
  시드는 `structural` 호출 그래프와 SAST 리드.
- **B(부재 트랙)** 는 *entry-first*다. 라우트에서 출발해 **앞으로** 걸어 리소스 로드까지 가고
  그 경로 어딘가에 authz/소유권 게이트가 있는지 묻는다. 도구는 여기서 거의 장님이다. "소유권 검사
  없음"은 grep 패턴이 아니라 애플리케이션 이해를 요구한다. 시드는 `comprehension` 레이어와
  `_authz_matrix.json`.

한 에이전트에 둘을 합치면 도구 모양이 잡힌 쉬운 injection 쪽에 과투자하고 정작 추론이 필요한
로직 버그를 날린다. 역할 둘, 시드 둘, 사고방식 둘로 가는 이유가 그것이다. METHODOLOGY가 트랙
이름을 클래스가 아니라 **결함 모양**으로 다시 붙인 것도 같은 맥락이다(§2.2).

### 1.5.2 왜 병렬 + 스트리밍인가 (순차가 아니라)

프로듀서는 **폭에 묶여 있고**(커버할 모듈이 수십 개), 컨슈머는 **깊이에 묶여 있다**(파인딩 하나당
수 초에서 수 분의 라이브 작업). A/B가 끝난 *뒤에* C를 돌리면 스캔 내내 재현 기계를 놀리다가 마지막에
모든 재현을 직렬로 몰아서 하게 된다. 스트리밍은 그 둘을 겹친다. A/B가 20번째 결함을 발견하는 동안
C는 1번을 재현한다. **피드백 루프**도 이래야 실제로 돈다. C가 파인딩을 `needs_reanalysis`로 넘기면
아직 살아 있는 E가 그 자리에서 집어 간다. 배치 파이프라인은 전체 패스를 한 번 더 돌지 않고는 이걸
못 한다.

### 1.5.3 다섯 세션이 어떻게 어긋나지 않나 (어려운 부분)

다섯 역할은 서로 말을 걸지 않는 별개의 OS 프로세스다. 조율은 전부, 다섯 모두와 사람이 들여다볼 수
있고 재시작을 넘겨 살아남는 한 군데를 거친다. **파일시스템**(`workspace/`)이다. 데이터베이스도,
메시지 브로커도, 소켓도 필요 없다. 파일시스템은 durable하고 설치할 게 없고 `ls`/`cat`으로 보인다.

**큐가 곧 디렉터리다.** `workspace/findings/`에 파인딩 하나당 JSON 하나. 파일의 *존재*가 "큐에
들어왔다"이고 `status` 필드가 "생애주기 어디쯤인가"다. 프로듀서는 파일을 더하고 컨슈머는 디렉터리를
훑어 제자리에서 다시 쓴다. 별도의 큐 서버가 없으니 디렉터리 목록 자체가 큐 상태이고 그래서
`queue.py`가 `glob` + 카운터 한 줌으로 끝난다.

**아이덴티티와 중복 제거는 content-addressed다.** `write_finding.py`가
`id = sha1(track | vuln_class | sink.file | sink.line)[:16]`을 계산한다. 두 번의 패스(또는 두
프로듀서)가 **같은 버그 클래스로 같은 싱크**에 내려앉으면 **같은 id**, 따라서 같은 파일명이 나온다.
재발견이 중복 파일을 만드는 대신 *기존 파일 위로 접힌다*. 쓰기가 **같은 아이덴티티에서 멱등**이라는
뜻이고 이게 A와 B(그리고 각자의 반복 패스)를 이중 집계 걱정 없이 풀어놓을 수 있게 하는 동기화다.
싱크 라인을 못 잡은 degenerate한 경우(매니페스트 수준 항목, 동적 디스패치)에만 `sink.symbol`을
키에 더해 한 파일의 모든 파인딩이 한 id로 뭉개지는 것을 막는다.

**동시성 안전장치는 파인딩 단위 락이다.** `<id>.json`을 건드리기 전에 writer가 `<id>.json.lock`에
배타 `fcntl.flock`을 건다. *같은* 파인딩을 쓰는 두 프로세스는 직렬화되고 반쯤 쓰다 만 JSON이
섞이는 일은 없다. content-addressed id와 합쳐지면 경합 구간이 아주 좁다. 정확히 같은 파인딩에서만
락이 부딪친다.

**이력은 append-only, 갱신은 merge다.** 파인딩이 이미 있는데 명시적 업데이트가 아니면 writer는
*원본을 유지하고* `history` 항목만 하나 덧붙인다("다시 봤다"). 다른 세션의 데이터를 덮어쓰지
않는다. `--update <id>`면 새 필드를 기존 객체에 *머지*하고 `history` 전체를 보존한다. 그래서 파일은
마지막 writer가 이기는 대신 여러 세션의 사실을 쌓아간다. `history` 배열이 다섯 역할을 가로지르는
감사 추적이다.

**`status`가 인계 신호다.** 생애주기 필드는 디스크에 사는 작은 상태 기계이고 프로듀서와 컨슈머가
*직접 대화하지 않고* 조율하는 방법이다. `candidate`(프로듀서 할 일 끝, 컨슈머 가져가라) →
`cross_validated` → `reproduced` → `confirmed`, 또는 `not_product_vulnerability`(재현은 됐지만
벤더 경계를 넘지 않음) / `needs_reanalysis`(E에게 넘김) / `false_positive`(탈락). C는 종단이 아닌
상태를 폴링하고 E는 `needs_reanalysis`만 폴링한다. 공유 필드 하나가 프로세스 간 메시징을 대신한다.

**파생 상태는 다시 만들지, 묵은 걸 믿지 않는다.** `report.md`와 `report/<id>/`는 `findings/`에서
*파생된다*. 증분으로 동기화를 유지하려다 드리프트가 생기는 대신(정확히 "파인딩은 있는데 리포트는
0건"이라는 버그다) 대시보드가 매 사이클 **원천에서 다시 유도한다**. 진실의 원천은 `findings/`고
나머지는 전부 그것의 순수 함수다.

### 1.5.4 *생애주기*는 어떻게 맞추나 (역할별 supervisor + `_stop`)

에이전트 턴은 유한하다. `audit.sh`의 `supervise()`는 역할 하나당 서브셸 루프를 하나 만들고 그
안에서 역할 명령을 실행하고 끝나면 `budget_guard.py --check`를 한 번 돌린 뒤 5초 쉬고 다시
실행한다. 루프 조건은 `workspace/_stop`이 없고 `DEADLINE`(= `MAX_HOURS`) 전일 것. `_stop`은 공용
kill switch고 `workspace/_pids`에 다섯 supervisor PID와 (떠 있다면) canary PID가 들어간다.
`budget_guard.py`는 세션 로그에서 누적 토큰을 긁어 `TF_TOKEN_BUDGET`을 넘으면 `_stop`을 touch해서
모든 supervisor가 다음 루프 검사에서 알아서 내려가게 한다. 토큰 표식을 하나도 못 찾으면 0을 보고하고
절대 멈추지 않는다(fail-open). 기본값 `TF_TOKEN_BUDGET=0`은 가드 자체를 끈다.

### 1.5.5 설계가 여기까지 온 경로 (리팩터와 그 이유)

아래는 전부 실제로 깨져서 경계를 바꾼 사례다.

| from | to | why |
|---|---|---|
| 순차 파이프라인 | A/B/C 병렬 스트리밍 + D + E | 폭(찾기)과 깊이(재현·무기화)를 겹치고 라이브 피드백을 살린다 |
| 모듈마다 codex를 다시 부르는 셸 루프 | 역할당 길게 가는 자기주도 세션 하나 | 모듈 루프가 매 반복마다 에이전트 기억을 리셋했다 |
| 독립 `codex exec` supervisor 네 개 | supervise된 root 하나 + 커스텀 서브에이전트 넷 | 역할 정체성을 네이티브로 두고 root가 스레드를 직접 조율하게 하려고 |
| supervise된 root + 서브에이전트 | **역할별 독립 supervise 세션 다섯(A–E)** | 백엔드를 둘로 늘리면서 역할 정의가 `.codex/agents/*.toml`에만 살 수 없게 됐다. mission 텍스트를 `audit.sh` 안으로 옮기고 역할마다 자기 루프를 줬다 |
| 네 역할(A/B/C/D) | **다섯(+E)** | C가 `needs_reanalysis`를 직접 재조사하면 큐가 멈춘다. 되돌아온 항목만 전담하는 역할을 뗐다 |
| 도구가 파인딩을 작성(semgrep→finding) | **에이전트**가 작성, 도구는 힌트만 | semgrep 주도 실행은 파인딩 0건을 냈고(PHP 룰 부재) 판단이 없었다 |
| Semgrep OSS | OpenGrep | Semgrep OSS 코어가 아주 큰 저장소에서 segfault한다 |
| C가 스스로 끝났다고 판단 | supervisor 재시작 + "혼자 멈추지 마라" | C가 시작 직후 빈 큐를 보고 프로듀서가 쓰기도 전에 종료했다 |
| 병합된 `report.md` 하나 | 취약점별 `report/<id>/{poc.py,finding.md}` | 고정 2단계 PoC 템플릿이 틀렸다(pre-auth와 다단계는 모양이 다르다). PoC는 버그마다 에이전트가 써야 한다 |
| 재현되면 바로 `confirmed` | 재현 → **공식/벤더 제품 경계 리뷰** → `confirmed` | 동작하는 PoC는 동작을 증명할 뿐 제품 취약점을 증명하지 않는다. 문서화된 위험이나 앱 설정 실수가 0-day로 올라갔다 |
| 백그라운드 supervisor가 셸 fd를 상속 | fd 분리(`</dev/null >…`) | 상속된 fd가 부모 셸을 붙잡아 `start.sh`가 "launching…"에서 멈추고 tmux까지 못 갔다 |
| `tiled` + 인덱스 기반 패널 라벨 | 캡처한 pane **id**에 라벨 바인딩 | tiled 레이아웃이 패널 번호를 다시 매겨 라벨이 엉뚱한 패널에 붙었다 |
| 안드로이드 + DBMS 퍼징 + `harnesses/` | **웹 전용** | 세 갈래를 한 저장소에서 끌고 가니 역할 계약과 스키마가 서로 다른 타깃 모양을 동시에 설명해야 했다. 웹 소스 평가만 남겼다 |

관통하는 원칙은 하나다. 결정론은 한 번만 도는 도구로 밀어 넣고 판단은 좁게 초점 잡힌 에이전트로
밀어 넣고 독립 프로세스들은 durable하고 content-addressed한 파일로만 조율한다.

---

## 1.6 분석 방법론의 근거 — 모델 먼저, 싱크 먼저, 가설 세우고 검증

이 절은 TaintForge가 코드를 분석하는 *방식*의 근거다. 왜 코드베이스를 그냥 LLM에 던지지 않는지,
왜 도구가 만든 모델을 먼저 세우는지, 왜 싱크에 닻을 내리는지, 왜 모든 리드가 *검증해야 할 가설*인지.
취향 문제가 아니라 LLM과 실제 코드베이스가 실제로 어떻게 굴러가는지에서 따라 나온다.

### 1.6.1 "코드베이스 전체를 LLM에 주면 안 되나?"

저장소를 통째로 붙여 넣고 "버그 찾아"라고 하는 순진한 방법은 실제 애플리케이션에서 구체적인
이유로 실패한다.

- **들어가지도 않고 크기에 따라 recall이 무너진다.** 중간 규모 앱이 파일 수천 개, 큰 앱은 수만
  개다. 어떤 컨텍스트 윈도도 못 담고 담긴다 해도 어텐션이 균일하지 않다. 소스와 싱크가 서로 다른
  파일에 있고 수천 토큰 떨어져 읽히는 취약점이야말로 모델이 놓치는 장거리 의존성이다. 전부 쏟아
  넣으면 감사가 아니라 얕은 훑기가 나온다.
- **버그는 비지역적인데 읽기는 지역적이다.** SQL injection은 "한 줄"인 경우가 드물다. 공격자 입력이
  컨트롤러에 들어와 서비스를 지나 세 콜 떨어진 쿼리 빌더에 닿는다. 파일을 하나씩 읽는 모델은 어떤
  먼 함수가 이 싱크를 먹이는지 알 길이 없다. **코드가 어떻게 연결되는지의 지도**가 필요하고 그
  지도는 판단이 아니라 *구조적 사실*이다.
- **"끝났다"는 개념이 없다.** 자유형 "버그 찾아"에는 커버리지 보장이 없다. 눈에 띈 것만 보고
  멈춘다. "모든 모듈을 검토했다"고 말할 방법이 없는데, 보안 감사에서는 그게 핵심이다.
- **비용과 비결정성.** 질문할 때마다 구조를 다시 유도하면 토큰을 태우고 매번 조금씩 다른 구조가
  나온다.

그래서 설계가 **두 종류의 일을 분리한다**. 기계적 구조 추출(싸고 정확하고 한 번만, 도구로)과
의미 판단(비싸고 흐릿하고 모델로). 파서가 몇 초면 완벽하게 뽑는 호출 그래프를 모델이 한정된
어텐션을 써서 재구성할 이유가 없다.

### 1.6.2 왜 모델(Code Model)을 먼저 세우나

Code Model(`workspace/CODE_MODEL.json`)은 모델이 재구성하는 대신 *그 위에서* 추론할 수 있게
도구가 만들어 둔 지도다. 두 레이어로 설계했다.

- **`structural`(도구, ast+regex).** 파일, 엔트리 포인트, 그리고 **호출 그래프** —
  `caller → callee` 엣지에 더해 위험한 프리미티브 호출(`query`, `exec`, `unserialize`, `include`,
  …)을 표시한 `<builtin-sink>` 엣지. 모델이 지역적 읽기로는 못 믿을 연결성인데 파서는 정확히
  뽑는다. 분석이 **파일을 넘는 흐름을 따라가게** 만드는 부분이다.
- **`comprehension`(LLM).** 라우트, 권한 모델, 신뢰 경계, 사용자 여정 — 파서가 못 뽑는 *의미*.
  진짜 판단이라 모델이 하되, **한 번만** 해서 적어 둔다. 그래야 모든 세션이 같은 이해를 공유한다.

이 분할은 핵심 원칙을 분석 층위에서 다시 말한 것이다. 사실은 도구가 말하고 해석은 모델이 한다.
호출 엣지는 사실이고 "이 엣지는 새니타이저를 지나치지 않은 오염 데이터를 나른다"는 해석이다. 둘을
섞으면(모델에게 파서 노릇까지 시키면) 양쪽 다 나빠진다.

Code Model은 커버리지를 *측정 가능하게* 만들기도 한다. 코드베이스가 모듈과 그래프로 열거돼 있으니
**모든** 모듈/싱크를 방문해 판정을 남기게 몰아붙일 수 있다. 버그를 찾거나, 안전한 이유를 대거나.

### 1.6.3 왜 sink-first인가 (위험한 끝에 닻을 내리고 거꾸로 추적)

오염을 쫓는 방향은 둘인데 비용이 같지 않다.

- **source-first(정방향):** 모든 입력(`$_GET`, 요청 본문, …)에서 출발해 위험한 데 닿기를 바라며
  앞으로 따라간다. 입력은 *어디에나* 있고 대부분의 흐름은 무해하다. 탐색이 폭발적으로 퍼져나가
  대개 막다른 길로 간다.
- **sink-first(역방향):** **유한하고 열거 가능한** 위험 연산 집합(`<builtin-sink>` 엣지)에서
  출발해 호출 그래프를 **거꾸로** 걸으며 공격자 입력이 닿을 수 있는지 본다.

sink-first가 이기는 건 **위험한 집합은 작고 알려져 있는데** 입력 집합은 거대하기 때문이다. 모든
실제 취약점은 싱크에서 *끝난다*. 싱크가 없으면 버그도 없다. 그래서 싱크를 열거하면 문제가 "이 N개의
위험한 자리 각각에 오염 데이터가 올 수 있나?"로 묶인다. 싱크당 다룰 만하고 확인 가능한 질문이고
`callgraph.py --callers <sink>` / `--trace`가 정확히 그 역방향 경로를 준다. 트랙 A가 말 그대로 이
루프다.

트랙 B는 같은 발상을 *리소스* 끝에 적용한다. 라우트에서 출발해 **앞으로** 리소스 로드까지 가서 그
경로에 authz/소유권 게이트가 앉아 있는지 묻는다. 철학은 같다. 보안상 의미 있는 지점에 닻을 내리고
거기까지의 경로를 검사한다. 다만 여기서 "싱크"는 위험한 호출이 아니라 "객체가 로드되거나 반환되는
지점"이다.

단, 두 방향 중 하나만 도는 것 자체가 METHODOLOGY가 경고하는 편향이다(§2.7). 양쪽 트랙이 각자
한 방향을 맡되, 한 트랙 안에서도 소스에서 정방향(`callgraph.py --forward`)과 싱크에서 역방향을
모두 돌리는 게 계약이다.

### 1.6.4 왜 가설-검증인가 (도구 히트가 왜 가설일 뿐인가)

TaintForge의 모든 리드는 결론이 아니라 **취약점에 대한 가설**로 다룬다. 리드를 *만들어내는* 두
주체 모두 혼자서는 못 믿을 물건이기 때문이다.

- **정적 도구는 과잉 주장한다.** SAST 히트(OpenGrep)는 "패턴이 맞았다"지 "익스플로잇 가능하다"가
  아니다. 헬퍼 안의 새니타이저도, 자동 이스케이프하는 프레임워크도, 세 프레임 위의 가드도 못 본다.
  이걸 파인딩으로 취급하면 출력 대부분이 오탐이다.
- **LLM은 흐름을 지어낼 수 있다.** 코드를 추론하다 보면 읽지 않은 검사가 막아 주는 경로를
  익스플로잇 가능하다고 스스로 납득하거나 그 반대로 간다.

그래서 파이프라인이 **단계마다 입증 책임을 올리는 깔때기**로 짜여 있고 `status` 필드가 곧 가설
강도의 사다리다.

```
candidate                   그럴듯한 흐름이 있다 (분석가 한 명의 추론)        — 가장 약함
cross_validated             독립 엔진이 패턴이 실재한다고 동의               — 보강됨
reproduced                  살아 있는 인스턴스에서 실제로 터졌다 (PoC)        — 동작 증명
confirmed                   재현 + 공식/벤더 제품 경계 리뷰 + 증거 계약       — 가장 강함
   ↑ false_positive (반증, 탈락) / not_product_vulnerability (동작은 진짜지만 벤더 버그가 아님)
   / needs_reanalysis (판단 불가, E에게)
```

- **교차 검증**은 분석가 한 명의 사각지대를 막는다. 후보가 올라가려면 두 번째 *독립* 방법
  (CodeQL/OpenGrep)이 동의해야 한다. 실패 양상이 다른 두 방법의 일치는 어느 한쪽보다 훨씬 강하다.
- **동적 재현이 결정적 시험이다.** 익스플로잇 가능성 가설은 *실제로 해 봄으로써* 결판난다. 페이로드를
  쏘고 교차 사용자 요청을 리플레이하고 SSRF canary를 때린다. 라이브 시스템이 오작동하거나 아니거나
  둘 중 하나다. 믿음이 증거(`repro` + `poc.py`)로 바뀐다. 쏠 수 없는 것은 주장하지 않고 정직하게
  `needs_reanalysis`로 표시한다.
- **공식/벤더 제품 경계 리뷰**가 그다음 층이다. 재현된 동작이 벤더가 지원하는 보안 경계를 넘는지
  1차 자료와 대조한다. 동작하는 PoC는 동작을 증명할 뿐 제품 취약점을 증명하지 않는다.
- **공개 이력 조사**는 *입증된* 제품 버그 위에 올라가는 마지막 검증층이다. 정말 새 것인지, 이미
  공개된 수정인지. 가장 센 주장(0-day)이 가장 센 검증을 받는다.

도구가 파인딩을 직접 쓰지 않고 에이전트가 쓰는 이유도 여기 있다. 가설은 세울 추론자와 결판낼 시험이
필요한데, 패턴 매처는 *어디를 볼지* 제안만 할 수 있다. 도구에 파인딩 작성권을 줬던 초기 버전이 "실제
파인딩 0건 / 전부 오탐"을 낸 그 실패다.

### 1.6.5 루프 요약

```
build a MODEL with tools     ->  facts (call graph, routes, proof ledger), do-once, exact
form HYPOTHESES on the model ->  sink-first backward taint (A) / entry->resource (B)
                                 seeded by SAST leads + the model, authored by the agent
VERIFY, escalating proof     ->  cross-validate (independent engine)
                                 -> reproduce live (PoC: probe / canary / browser_probe)
                                 -> official/vendor product-boundary review
                                 -> public-history review (known vs novel)
record verdict per unit      ->  every route/sink unit: a finding or a justified "safe"
```

모델 먼저는 분석가에게 파일 더미 대신 지도를 준다. 싱크 먼저는 무한한 사냥을 유한한 체크리스트로
바꾼다. 가설-검증은 도구의 오탐과 모델의 환각이 리포트까지 가는 길을 둘 다 막는다. 선택마다 관찰된
구체적 실패가 하나씩 뒤에 있다.

### 깊이 — 한 번 훑기가 아니라 체인 만들기

sink-first 커버리지는 알아볼 수 있는 싱크가 있는 버그를 찾는다. 그것만으로는 *개별적으로는 무해한
단계들의 체인*인 고위험 버그군을 못 찾는다. 날 참조를 돌려주는 파서, `hasOwnProperty` 없는 프로퍼티
워크, 끝에 닿는 생성자 — 어느 한 줄도 "그 싱크"가 아니고 취약점은 조합에만 존재한다. 사람 연구자가
파서/역직렬화기/디스패처를 한 줄씩 읽으면서 "공격자가 이걸 제어하면 다음에 뭐가 열리지?"를 반복해서
묻고 얻은 능력을 계속 들고 가는 방식으로 찾는 종류다.

에이전트가 훑고 지나가는 대신 그렇게 분석하도록 모델 먼저 / 싱크 먼저 위에 세 장치를 얹었다.

1. **딥다이브 지시**가 모든 프로듀서 브리핑에 들어간다. 파싱하거나 역직렬화하거나 이름·문자열로
   디스패치하거나 리플렉션하거나 사용자 제어 프로퍼티 경로를 걷는 코드에서는 스캔을 멈추고 공격자
   제어 값이 각 단계에서 무엇을 가능하게 하는지 단계별로 추론한다.
2. **리드 노트**(`_shared/leads.py`, 파인딩 writer와 같은 방식으로 file-lock)가 한 번 패스면 버려질
   중간 재료를 기록한다. `lead`(아직 버그는 아닌 흥미로운 관찰, 무엇을 `enables`하는지 포함),
   `primitive`(확인된 능력), 타깃별 `note`(재시작을 넘겨 살아남는 진행 상태), 그리고 후보 체인을
   이루는 `link`.
3. **딥다이브 우선 커버리지**: `coverage.py --next`가 파싱/역직렬화/디스패치/템플릿/리플렉션을
   암시하는 이름의 모듈 우선순위를 올린다. 조합 버그가 모이는 곳에 유한한 분석 시간을 쓴다.

C와 D 세션은 후보 체인을 읽고 끝에서 끝까지 하나의 연결된 파인딩으로 실현하려 시도한다. 리드는 혼자서
파인딩으로 승격되지 않고 아직 버그가 아니라는 이유로 버려지지도 않는다. 다른 세션이 쌓는 체인을
완성할 수 있어서다. 대가는 비용이다. 깊게 읽기는 훑기보다 훨씬 비싸고 그래서 커버리지가 보상이 클
모듈 쪽으로 깊이를 조향한다.

---

## 2. METHODOLOGY.md — 모든 역할이 묶이는 방법론 계약

`.agents/skills/_shared/METHODOLOGY.md`는 `AGENTS.md` 다음, 역할 스킬 앞에 읽는다. 언어·타깃·클래스와
무관하게 쓰였고 메모리 안전성도 여러 도메인 중 하나로만 다룬다. 역할 미션 텍스트가 이 파일을 명시적으로
지목하기 때문에 A/B/C/D/E 전부가 여기에 묶인다.

> **이 장은 그 파일의 한국어 설명이고, 단일 진실 원천은 `METHODOLOGY.md` 쪽이다.** 둘이 어긋나면
> 영문 파일이 맞고 이 장이 낡은 것이다. 역할이 실제로 읽는 건 영문 파일이기 때문이다. 방법론을
> 바꿀 때는 `METHODOLOGY.md`를 먼저 고치고 이 장을 따라 맞춘다.

### 2.1 전제 1 — 세 다리

대부분의 분석가와 모든 도구는 *source 편향*이거나 *sink 편향*이거나 *propagation을 건너뛰어서* 버그를
놓친다. flow 모양의 결함은 세 다리가 전부 명시적으로 적혀야 존재한다. 가정한 다리는 파인딩이 아니라
리드다.

### 2.2 전제 2 — 두 가지 결함 모양, 그리고 트랙 이름

결함은 두 모양으로 온다.

- **(A) dangerous flow** — 오염이 위험한 연산에 닿는다.
- **(B) missing control** — 도달 가능한 경로에 있어야 할 검사가 없다.

접근 제어, 인증, 대부분의 로직 버그가 (B)다. (A)만 사냥하면 (B)를 통째로 잃는다. **트랙은 클래스가
아니라 모양을 따라 이름 붙었다.** 트랙 A는 flow 트랙, 트랙 B는 부재 트랙이다. 어떤 클래스든 두 모양을
다 가질 수 있으니 모양을 *먼저* 정하고 거기서 라우팅한다. 판단은 파인딩에
`defect_shape: "flow" | "missing_control"`로 기록한다.

### 2.3 §0 위협 모델 먼저 — 건너뛰면 방향이 없다

사냥 전에 네 가지를 적는다. 워크스페이스에 이미 자리가 있다.

| What | Where it lives | Built by |
|---|---|---|
| Entry points | `CODE_MODEL.structural.entry_points`, `proof_ledger.json` | `build_code_model.sh` |
| Actors & trust boundaries | `CODE_MODEL.comprehension.{route_map,permission_model,trust_boundaries}` | source-model (사람/에이전트) |
| Assets | `CODE_MODEL.comprehension.service_identity.sensitive_data` | source-model |
| Invariants | `HYPOTHESES.json` (`invariant` + `attacker_goal`) | hypothesize |

- **Entry points:** 라우트, 핸들러, RPC, 큐 컨슈머, CLI, 웹훅, cron, 파일 파서, 역직렬화 진입점,
  IPC, 프로토콜 wire reader.
- **Actors / trust boundaries:** unauthenticated / authenticated / per-role / per-tenant /
  internal-service. 엔트리 포인트 **하나하나**마다 *누가 이 코드에 닿는가*를 — 라우트 이름으로 추측하지
  말고 호출 체인으로 증명해서 — 가장 낮은 권한으로 적는다.
- **Assets:** 비밀, 자격증명, PII, 자금, 권한 상태, 무결성이 중요한 데이터, 가용성.
- **Invariants:** 코드가 말없이 참이라고 믿는 것. 소유권, `balance >= 0`, 상태 기계 순서, "여기까지
  왔으면 인증된 것", "이 포인터는 살아 있다", "이 길이는 이 버퍼와 맞는다". **불변식 목록이 곧 후보
  버그 목록이다.**

엔트리 포인트 × 최소 권한 표가 안 나왔으면 위협 모델을 한 게 아니다. 모든 파인딩의 `reachability`가
그 표에서 나온다.

### 2.4 §1 SOURCE 카탈로그 — "입력"이 아니라 "공격자 영향"

여덟 계열이다. 4~7번은 taint 엔진에도 구조적 호출 그래프에도 안 보이고 lifetime과 에러 경로를 읽어야만
나온다.

1. **Direct input** — 요청 파라미터/헤더/쿠키/본문, 업로드, env, IPC, 역직렬화 바이트, 파일,
   프로토콜 프레임.
2. **Identity & authorization state** — 세션, 토큰, 역할, 테넌트 id, 소유자 id. 공격자가 *고르거나
   위조하거나 혼동시킬* 수 있는 것은 전부 소스다. 아이덴티티를 공격자 영향이 아니라 신뢰할 수 있는
   컨텍스트로 취급하는 것이 shape (B) 누락의 가장 흔한 원인이다.
3. **Second-order / stored** — DB, 캐시, 설정, 로그에 썼다가 나중에 신뢰된 값으로 읽는 것(stored XSS,
   second-order injection, log-to-template).
4. **Post-free un-reset state** — free/close됐는데 전역, 구조체 필드, 레지스트리가 아직 참조하고 있다가
   재사용되는 포인터·핸들·fd·객체. UAF의 뿌리.
5. **Bailout-orphaned state** — 예외, `longjmp`, panic, early return, OOM, 타임아웃이 정리를 건너뛰어
   남은 상태. 정상 경로는 깨끗하고 에러 경로가 더럽다.
6. **Cross-scope persistent state** — 요청 사이(워커/프로세스 재사용), 스레드 사이, 워커 사이(공유
   메모리), 캐시를 통해 넘어가는 상태.
7. **Uninitialized reuse / metadata mismatch** — pool/arena 잔재, 또는 자기가 설명하는 객체와 어긋나는
   길이·타입·소유권·refcount 필드.
8. **Time & ordering** — 동시 인터리빙, 재진입, nonce/토큰/일회성 동작의 리플레이. 모든 TOCTOU와 레이스의
   소스 다리.

### 2.5 §2 class × shape 매트릭스 — 전수로 돌리고 모양으로 라우팅한다

클래스마다 두 모양이 다 있다. **owner** 열은 어느 트랙이 파일링하는지를 정해서 A와 B 사이로 떨어지는
클래스가 없게 만든다.

| Class | (A) dangerous flow | (B) missing control | Owner |
|---|---|---|---|
| Access control / authz | object id from input → load/mutate with no ownership check | is there an authz check on *every* path to each privileged op? horizontal/vertical escalation, tenant isolation | B |
| Authentication | token/session value trusted unverified | auth bypass, weak/fixated session, MFA-skipping path | B |
| Injection | input → SQL/NoSQL/cmd/code/LDAP/template/XSS/CRLF | no parameterization, no context-correct encoding | A |
| SSRF / request forgery | input URL → server-side fetch (http/dns/socket) | no destination allowlist, no metadata-IP block; no CSRF token | A (SSRF) / B (CSRF) |
| Path & file | input → path (traversal/LFI/RFI), upload name/type | no normalization, no root confinement, no type check | A |
| Deserialization / object injection | untrusted bytes → `unserialize`/`pickle`/gadget | no type allowlist, no signature | A |
| Memory safety | input or post-free state → `memcpy`/index/deref/function pointer | no length, NULL, or lifetime guard (UAF/OOB/type confusion) | A |
| Concurrency / TOCTOU | shared state mutated between check and use | no lock, no atomicity, no idempotency | B (logic/state), A (memory/lifetime races) |
| Crypto | secret/input → weak algorithm, fixed IV, non-constant-time compare | no verification, predictable randomness, plaintext storage | B |
| Resource / DoS | input size/count → unbounded alloc, loop, recursion | fd/lock/memory never released, no rate limit or quota | A (flow) / B (absence) |
| Information disclosure | internal state/secret → response, error, log, timing, cookie | no masking, no minimization, debug surface enabled | A |
| Business logic | input → invariant violation (negative qty/price, out-of-order, replay) | no state machine, no limit, no idempotency, no server-side validation | B |
| Config / supply chain | — (almost always absence) | default credentials, excess privilege, unsafe default, poisoned dependency | B |

규칙:

- **주인 없는 클래스는 없다.** 어느 트랙도 명백히 소유하지 않으면 발견한 역할이 `defect_shape`를 채우고
  왜 거기 있는지 한 줄 붙여 파일링한다.
- 트랙 A는 "로직처럼 보인다"고 버리지 않는다. 트랙 B도 "injection처럼 보인다"고 버리지 않는다.
  일단 파일링한 뒤 `correlation_id`를 걸어 C가 중복을 제거하게 둔다.
- E는 양 트랙의 파인딩을 모두 다시 연다.

### 2.6 §3 SINK / 위험 연산 분류 (shape A)

일곱 그룹 전부를 사냥한다. 한 그룹만 보면 그 그룹만 나온다.

1. **Execution** — `system`/`exec`/`eval`/`popen`, `include`/`require`, 역직렬화, 템플릿 렌더,
   동적 import/플러그인 로드.
2. **Query & storage** — SQL/NoSQL/ORM raw, 파일 쓰기, 외부 API 호출.
3. **Network** — 서버 측 fetch(http/socket/dns) → SSRF.
4. **Disclosure outputs** — 응답 헤더, 쿠키, 본문, 에러 메시지, 로그, URL 재작성, **타이밍**.
5. **Memory** — `memcpy`/`memmove`/`strcpy`(길이/오프셋), 배열 인덱스, 포인터 연산, 역참조, 함수 포인터.
6. **Privilege & control** — 역할/소유권/플래그 쓰기, vtable/핸들러/디스패치 테이블, 리다이렉트 목적지.
7. **Resource** — 무제한 alloc/루프/재귀, lock/fd 획득.

> **알려진 사각지대.** `build_code_model.sh`가 만드는 구조적 싱크 집합은 high-signal만 담는다
> (sql / command / code-eval / deserialization / file-path / ssrf-net / redirect). 그룹 4, 5, 6, 7은
> 기본 ledger에 **없다**. `TF_NOISY_SINKS=1`로 다시 빌드하거나 `callgraph.py --callers <symbol>`로
> 손수 열거한다. 그 네 그룹에서는 "ledger에 싱크가 없었다"가 안전의 근거가 되지 않는다.

### 2.7 §4 전파와 도달성 — 데이터 흐름이 아닌 엣지들

taint는 엣지 한 종류다. 여섯 가지를 다 추적한다.

1. **Trust-boundary transition** — unauthenticated → authenticated 리소스, 테넌트 A → 테넌트 B,
   저신뢰 저장소 → 고신뢰 소비자.
2. **Control-flow skip** — 예외, bailout, `longjmp`, early return, 재시도가 검사나 정리를 건너뛴다.
   *정상 경로에 있는 검사가 에러 경로에는 없을 수 있다.* 에러 경로는 따로 추적한다(P6).
3. **Lifetime edge** — alloc → free → 같은 주소 재할당. UAF가 사는 곳이고 고전적 taint 분석은 못 본다.
4. **Scope transition** — 요청 A가 오염시킨 상태를 요청 B, 워커 B, 나중 잡이 소비한다(영속 상태, SHM,
   캐시, DB 왕복).
5. **Concurrency interleaving** — 검사와 행동 사이에 다른 스레드/요청이 쓴다.
6. **Bidirectional call graph** — 각 소스에서 정방향(*어디에 떨어지나?*) **그리고** 각 위험 연산에서
   역방향(*무엇이 닿나?*). 한 방향만 도는 게 바로 전제 1의 source/sink 편향이다.

```bash
callgraph.py --forward '<source_or_handler_symbol>' -d 8   # source → ?
callgraph.py --callers <dangerous_symbol>                  # ? → sink
callgraph.py --trace   <dangerous_symbol> -d 8             # backward paths
```

엣지 2~5는 그래프에 없다. 코드를 읽어야 나온다.

### 2.8 §5 필수 패스 — 하나 건너뛰면 그 계열 전체를 놓친다

파인딩 하나로 끝나는 법은 없다. 감이 아니라 `proof_ledger.py --next` / `coverage.py --next`가 몰아주는
대로 모든 패스를 소진할 때까지 돌린다.

| # | Pass | "끝났다"의 정의 | Owner |
|---|---|---|---|
| P1 | **Entry × privilege map** — 모든 엔트리 포인트에 거기 닿는 최소 권한과 그 권한이 건드릴 수 있는 민감 연산을 붙인다. pre-auth 도달성은 호출 체인으로 증명한다. | ledger의 모든 route unit에 권한이 붙음 | B |
| P2 | **Guard audit on privileged operations** (shape B) — 소유권·역할·상태·결제를 요구하는 모든 연산마다 authz/소유권/상태 검사가 *그 경로*에, *모든 호출자*에 실제로 앉아 있는가 | 모든 privileged op가 finding / safe+evidence / needs_reanalysis 중 하나 | B |
| P3 | **Invariant-violation sweep** — §0의 각 불변식을 깨는 입력·순서·동시성이 있는가 | `HYPOTHESES.json`의 모든 불변식이 검증 또는 반증됨 | B |
| P4 | **Long-lived lifetime sweep** — 포인터·핸들·fd·lock을 쥔 모든 전역/장수 필드마다 (a) 어디서 해제되고 (b) 어디서 리셋되며 (c) 그 사이에 bailout이 끼어들 수 있는가. 셋 다 참이면 후보 | 그런 필드 전부 분류됨 | A |
| P5 | **Taint → every sink family** — §1의 모든 소스를 §3의 **일곱 그룹 전부**로 정방향 전파한다. 특히 disclosure 싱크(헤더/쿠키/로그/타이밍)와 SSRF | 열거된 모든 sink unit에 처분이 붙음 | A |
| P6 | **Error/exception path diff** — 성공 경로에서 도는 검사·정리 집합과 실패 경로의 그것을 비교한다. 건너뛴 검사는 우회고 건너뛴 해제는 누수나 dangling 참조다 | 실패 경로가 있는 모든 가드된 연산이 비교됨 | A + B |
| P7 | **Cross-scope & concurrency topology** — 요청 재사용, 워커 재사용, 동시 실행을 가정하고 도달성을 다시 판정한다 | 모든 상태 보유 연산이 재사용 가정하에 판정됨 | A + B |

P4, P6, P7은 이 저장소에 도구 지원이 없다. 코드를 읽는 패스이고 스캐너를 살아남은 버그들이 사는 곳이다.

### 2.9 §6 가드레일 — 방법론의 함정들

- **두 모양을 다 돌린다.** source→sink만 쫓으면 접근 제어, 인증, 로직이 통째로 빠진다.
- **source-only 판정 금지.** 정보 노출이나 UAF 읽기는 관찰 지점(§3 그룹 4)이나 위험 연산에 닿기
  전까지는 결함이 아니다. 그 다리가 없으면 `lead`(`leads.py`)지 파인딩이 아니다. 어느 쪽인지 말한다.
- **첫 히트에서 멈추지 않는다.** 결함은 뭉쳐 있다. 같은 시그니처의 다른 인스턴스를 전부 쓸고 나서
  넘어간다.
- **계측 ≠ 결함.** 새니타이저, 디버그 assertion, 진단 프로브, 패치된 빌드에서만 나는 크래시는 리드다.
  정확히 stock 빌드에서 재생해야 파인딩이 되고 관찰이 어느 빌드에서 나왔는지 기록한다
  (`repro.instrumentation_only`, `repro.stock_replay`).
- **전제 조건과 버그를 분리한다.** 그 전제가 기본/벤더 출하 설정에서 성립하는지 말하고 아니라면 정확히
  어떤 비기본 설정인지 이름을 댄다(`preconditions`).
- **상승 천장은 증명하지 가정하지 않는다.** read → write, crash → control, self → other user, 각 단계는
  증명되거나 주장되지 않는다. 안 올라가면 "DoS only", "read-only", "self-only"로 못 박는다
  (`primitive.escalation_ceiling`, `primitive.ruled_out`). 과대 포장은 그 자체로 보고 결함이다.
- **도달성은 엔트리 포인트 *그리고* 권한이다.** "누가 이걸 트리거할 수 있나"에 호출 체인과 역할로
  답하지 추측으로 답하지 않는다(`reachability`).
- **하나의 근본 원인, 하나의 파인딩.** 트리거 변형은 같은 파인딩의 재현 케이스다. 패치 하나가 둘 다
  고치면 하나의 파인딩이고 `correlation_id`를 공유한다.

### 2.10 §7 출력 계약 — 스키마가 곧 보고 형식이다

산문으로 파인딩을 쓰지 않는다. 아래 요소는 전부 `schemas/finding.schema.json`의 필드고
`write_finding.py`를 통해서만 기록된다.

| Element | Field |
|---|---|
| class tag + CWE | `vuln_class`, `cwe` |
| which shape | `defect_shape` |
| mechanism | `evidence` |
| SOURCE → SINK | `source`, `sink`, `flow[]` (shape A) |
| missing control, and the path it is missing from | `missing_control{control,expected_at[],unguarded_path,actor}` (shape B) |
| reachability (entry point, privilege, pre-auth, call chain) | `reachability{entry_point,min_privilege,pre_auth,call_chain[]}` |
| preconditions (default vs non-default) | `preconditions{default_configuration,required_settings[],notes}` |
| primitive and escalation ceiling | `primitive{kinds[],escalation_ceiling,ruled_out[]}` |
| affected assets | `assets_affected[]` |
| reproduction & reliability | `repro{poc,response,reliability,instrumentation_only,stock_replay}` |
| guards you ruled out | `sanitizers_seen[]` |

`vuln_class`에 쓰는 클래스 태그(kebab-case): `broken-access-control`, `auth-bypass`, `idor`,
`sql-injection`, `nosql-injection`, `command-injection`, `code-injection`, `ssti`, `xss`,
`ssrf`, `csrf`, `path-traversal`, `deserialization`, `xxe`, `open-redirect`, `use-after-free`,
`oob-read`, `oob-write`, `type-confusion`, `null-deref`, `toctou-race`, `crypto-misuse`,
`info-leak`, `dos`, `business-logic`, `misconfiguration`, `supply-chain`.

`write_finding.py`가 `confirmed`에서 이 계약을 강제한다. `reachability`, `preconditions`, 그리고 상승
천장이 비어 있으면 종단 보고 상태에 도달할 수 없다.

### 2.11 §8 보고 전 자체 점검

- [ ] 위협 모델을 먼저 했는가 — 엔트리 포인트, 신뢰 경계, 자산, 불변식?
- [ ] 두 모양을 다 돌렸는가? (§5 P2 가드 감사를 실제로 수행했는가?)
- [ ] shape-A 파인딩마다 세 다리가 전부 적혔고 가정한 게 없는가?
- [ ] 같은 시그니처의 다른 인스턴스를 쓸었는가? (전역, 불변식, privileged op)
- [ ] 정보 노출을 출력 싱크(헤더/쿠키/로그/타이밍)까지 추적했는가? SSRF 싱크를 확인했는가?
- [ ] 에러/예외 경로를 성공 경로와 비교해 건너뛴 검사와 정리를 찾았는가?
- [ ] 요청 간 / 워커 간 / 동시 재사용을 고려했는가?
- [ ] 계측 산물이 아니라 stock 빌드에서의 진짜 재현인가? 전제 조건이 기본값인가?
- [ ] 도달성이 "누가, 어떤 권한으로"로 적혔고 상승 천장이 과대 포장 없이 못 박혔는가?

---

## 3. 파인딩 계약 (`schemas/finding.schema.json`)

모든 것이 이 객체 하나를 통과한다. 스키마의 필수 필드는 `id`, `track`, `vuln_class`, `status`,
`detector`, `source`, `sink`, `created_at`이고 나머지는 생애주기를 따라 채워진다.

| field | who writes | meaning |
|---|---|---|
| `id` | writer | `sha1(track\|vuln_class\|sink.file\|sink.line)[:16]` — 안정적이고 content-addressed |
| `correlation_id` | C | 트랙·엔진을 가로지르는 중복을 한 근본 원인으로 묶는다 |
| `track` | producer | `A` 또는 `B` (이 둘뿐이다) |
| `defect_shape` | producer | `flow` 또는 `missing_control` |
| `vuln_class`, `cwe` | producer | 예: `sql-injection`, `CWE-89` |
| `severity_estimate` | producer | critical/high/medium/low/info — 잠정값이다 |
| `detector` | writer | `llm-track-a`, `llm-track-b`, `semgrep`, `opengrep`, `codeql` |
| `source`, `sink` | producer | `{file,line,symbol,description}`. shape B에서 `sink`는 privileged op 자신의 위치다 |
| `flow` | producer | shape A의 전파 단계들 |
| `missing_control` | producer | `{control,expected_at[],unguarded_path,actor,evidence}` (shape B) |
| `reachability` | producer→C | `{entry_point,min_privilege,pre_auth,call_chain[],notes}` |
| `preconditions` | producer→C | `{default_configuration,required_settings[],notes}` |
| `primitive` | producer→C→D | `{kinds[],escalation_ceiling,ruled_out[]}` |
| `assets_affected` | producer | 어떤 자산이 걸리는가 |
| `sanitizers_seen` | producer | 보고 배제한 가드들 |
| `evidence` | producer | 왜 취약하다고 보는가(오염 경로, 빠진 게이트) |
| `status` | producer→C/E | 아래 생애주기 |
| `repro` | C | `{attempted,success,poc,response,observation,env,reliability,instrumentation_only,stock_replay,poc_script}` |
| `official_review` | C | `{checked,verdict,sources[],rationale,product_version,default_configuration}` |
| `disclosure` | C | `{checked,status,references[],rationale,public_history}` |
| `exploit` | D | `{depth,primitive,max_impact,steps[],mitigations_bypassed[],constraints[],working_poc,oob_evidence}` |
| `hypothesis_id` | producer | 검증한 `HYPOTHESES.json` 항목 |
| `reanalysis_count` | writer | `needs_reanalysis`로 튕긴 횟수(재시도 상한용) |
| `history` | all | append-only 감사 추적 |

**상태 생애주기**

```
candidate --cross-val--> cross_validated --repro--> reproduced --official review--> confirmed
                                              |              |
                                  repro fails |              +--> not_product_vulnerability
                                              |                   (documented/expected/app config/unsupported)
                                              +--> false_positive
                                              +--> needs_reanalysis
```

- `candidate` — 프로듀서가 기록했고 C가 아직 안 봤다.
- `cross_validated` — 독립 엔진(CodeQL/OpenGrep)이 그 패턴이 실재한다는 데 동의했다.
- `reproduced` — 라이브 타깃에서 실제로 터졌다. 동작은 증명됐지만 제품 취약점이라는 뜻은 아직 아니다.
- `confirmed` — 재현 + 공식/벤더 리뷰가 `product_vulnerability` 또는 `known_vulnerability` + 증거 계약
  충족. 최종 보고 가능 상태.
- `not_product_vulnerability` — 재현은 됐지만 공식 판정이 `documented_hazard`, `expected_behavior`,
  `application_misconfiguration`, `unsupported_scenario` 중 하나다. 랭킹에서 빠진다.
- `false_positive` — 반증됨. 랭킹에서 빠진다.
- `needs_reanalysis` — 판단 불가. E에게 피드백으로 넘어간다.

프로듀서가 매긴 severity는 잠정값이고 **재현과 공식 제품 경계 판정**이 최종 순위를 지배한다.

---

## 4. Code Model과 시드 (`source-model`, `hypothesize` 스킬)

시드 단계에서 **한 번** 만들고 모든 세션이 재사용한다.

### 4.1 `build_code_model.sh` / `build_code_model.py` (structural, 도구)

**ast(python) + regex 추출기**로 뽑는다. tree-sitter 백엔드를 실제로 로드할 수 있는 인터프리터를
먼저 고르고(`TF_PY`로 지정 가능), 못 찾으면 regex로 떨어진다. 큰 TypeScript/Rust 트리에서 regex
fallback은 정확도를 많이 잃으니 인터프리터 선택 로그(`[info] interpreter: ...`)를 확인한다.

산출물:

- `workspace/CODE_MODEL.json` — `files`, `entry_points`, 그리고 **호출 그래프**(`caller -> callee`
  엣지). 위험한 프리미티브 호출(`query`, `exec`, `system`, `unserialize`, `include`, `require`,
  `eval`, `file_get_contents`, `curl_exec`, …)에는 `to: "<builtin-sink>"` 태그가 붙는다.
- `workspace/symbols.json` — 모듈/클래스/함수/메서드 심볼과 그 구간.
- `workspace/callsites.json` — 모든 호출 지점과 그것을 감싼 caller 심볼.
- `workspace/dataflow.json` — 구조적 source/sink/guard/path 골격.
- `workspace/proof_ledger.json` — 컨텍스트 안전한 커버리지를 위한 route/sink 분석 단위.

엔트리 포인트 탐지는 Python 계열 데코레이터(`@app.route`/`@app.get`/…), Spring `@GetMapping` 계열,
Express/Koa/Go 스타일의 `router.get('/x', handler)`(클라이언트 측 JS 디렉터리는 제외해서 수천 개의
가짜 엔트리 포인트가 진짜 서버 라우트를 덮지 않게 한다), PHP `Route::get(...)`, Rails 라우트와 Ruby
컨트롤러 액션(`index`/`show`/`create`/`update`/`destroy`/`new`/`edit`)을 다룬다.

큰 저장소에서는 자동으로 **graph-only**로 떨어진다. 분석 대상 파일이 `TF_GRAPH_ONLY_FILES`(기본 4000)를
넘으면 dataflow와 proof ledger를 건너뛰고 그래프 자체도 읽을 수 없을 만큼 커지므로 생략한다. 이게
`seed.sh`의 per-module 모델이 존재하는 이유다(§4.6). `--graph-only`로 강제하거나 `--force-paths`로
임계값을 무시할 수 있다.

`call_edges: 0`은 **구조 빌드가 실패했다는 뜻**이다. 추출기가 돌았는지 확인한다. 그래프는
함수/메서드 수준이고 호출 지점 라인을 포함하지만 여전히 골격이다. 입력에 바로 쓰는 싱크
(`include $_GET['x']`)는 엣지가 아니므로 에이전트는 항상 코드도 읽는다.

기본 싱크 집합은 high-signal만이다(sql / command / code-eval / deserialization / file-path /
ssrf-net / redirect). `TF_NOISY_SINKS=1`을 주면 resource-load(`find`/`where`/`first`/…)와
xss-output(`render`/`send`/…)도 싱크로 잡는다. 작은 앱에서는 유용하지만 ORM이 많은 큰 코드베이스에서는
proof ledger를 수만 단위로 터뜨릴 수 있어서 기본은 꺼져 있다.

### 4.2 `callgraph.py` (그래프 질의)

```bash
callgraph.py --stats                 # edge + builtin-sink counts (sanity check)
callgraph.py --entries               # entry points
callgraph.py --sinks                 # enumerated dangerous calls
callgraph.py --callers <symbol>      # who calls query/unserialize/include/...  (Track A entry)
callgraph.py --callees <symbol>      # what a route handler calls               (Track B entry)
callgraph.py --forward <symbol> -d 8 # source/handler -> where does it land?
callgraph.py --trace   <symbol> -d 8 # backward paths into a sink
callgraph.py -d N --limit N          # bound depth / result count
callgraph.py --model PATH            # use a non-default model (workspace/cm/<name>.json)
```

- **트랙 A**는 `--callers <sink>` 다음 `--trace`로 소스까지 **거꾸로** 간다.
- **트랙 B**는 `--entries`와 `--forward <handler>`로 **엔트리 → 리소스 접근**을 따라가며 빠진
  authz/소유권 게이트를 찾는다.
- `--model`은 per-module 모델을 질의할 때 쓴다. 전체 모델이 graph-only면 이쪽이 유일하게 쓸 만한
  입력이다.

### 4.3 `comprehension` (에이전트가 작성)

에이전트가 애플리케이션 이해를 Code Model에 채운다. `service_identity`, `route_map`, `feature_flows`,
`permission_model`, `user_journeys`, `trust_boundaries`. 트랙 B가 여기에 크게 기댄다. 권한 모델과
라우트를 모르면 "빠진 인가"를 추론할 수 없다. 결과는 `schemas/code_model.schema.json`으로 검증해야
한다. 정말 판정 불가한 필드는 추측해서 채우는 대신 비워 둔다.

### 4.4 `coverage.py` (전수성, 공격 표면 트리)

코드베이스를 **directory → module → entry point의 계층 트리**로 모델링한다. 한 번 훑고 마는 대신
에이전트가 유한한 덩어리로, 그것도 우선순위 순서로 전부 커버하게 만든다. vendor/tests는 제외하고
너무 큰 디렉터리는 쪼갠다(`TF_SPLIT_THRESHOLD` 기본 120, `TF_MAX_DEPTH` 기본 4). `--init`에서
`CODE_MODEL.json`을 읽어 각 모듈에 그 모듈이 노출하는 **엔트리 포인트**와 proof ledger 단위를 달아
두기 때문에, 커버리지가 디스크 위의 파일이 아니라 *도달 가능한 공격 표면*을 반영한다.

```bash
coverage.py --init <target>   # build the module tree -> workspace/coverage.json
coverage.py --next            # next pending module, ATTACK-SURFACE FIRST (routes before leaf libs)
coverage.py --done <module>   # mark a module analyzed
coverage.py --tree            # print directory->module->entry-point tree with per-node status
coverage.py --list            # list module paths
coverage.py --summary         # module progress + entry-point-surface progress separately
```

평평한 모듈 목록은 거의 빈 `vendor/` 덩어리와 라우트가 빽빽한 API 디렉터리를 같게 취급하고
`--next`는 그걸 알파벳 순으로 나눠 준다. 트리는 에이전트를 **공격자가 실제로 닿는 코드**로 먼저
끌어당기고 "커버리지 100%"의 뜻을 "모든 파일을 훑었다"가 아니라 "도달 가능한 모든 라우트를 안쪽으로
추적했다"로 바꾼다.

### 4.5 `proof_ledger.py` (단위별 증명 기록)

`coverage.py`가 모듈 단위라면 proof ledger는 route/sink 단위다. 단위마다 pending → done 상태와
`safe` / `finding` / `needs_reanalysis` 판정이 붙는다.

```bash
proof_ledger.py --summary                       # totals per route/sink unit
proof_ledger.py --list route|sink|all [--json]
proof_ledger.py --next route|sink|all           # highest-risk pending unit first
proof_ledger.py --show <unit_id> [--json]
proof_ledger.py --done <unit_id> --verdict safe --evidence "..."
proof_ledger.py --done <unit_id> --verdict finding --finding <finding_id>
proof_ledger.py --ledger workspace/cm/<name>.proof_ledger.json --next route
```

두 가지 게이트가 걸려 있다. `--verdict safe`는 `--evidence`로 10자 이상, 무엇이 이것을 안전하게
만드는 검사이고 왜 모든 호출자를 덮는지 이름을 대야 한다. 증거 없는 처분은 검증되지 않은 주장이고
`safe`는 단위를 영원히 닫는 주장이라 그렇다. `--verdict finding`은 `--finding <id>`를 요구하고 그
id의 파일이 `workspace/findings/`에 실제로 있어야 한다. 기억 속의 id를 가리킬 수 없다.

`--next`의 우선순위는 risk hint(`id-param`, `admin`, `state-changing`, `reaches-*`)와 싱크 카테고리
가중치(sql/command/code-eval 5, deserialization/ssrf-net/file-path 4, resource-load 3)로 계산한다.

### 4.6 `seed.sh` — 전체 색인 + per-module 전체 모델

```bash
./seed.sh targets/<app> [campaigns/<name>.modules]
```

하는 일:

1. 저장소 전체의 구조 색인(`build_code_model.sh`).
2. 모듈 파일이 주어지면 그 안의 각 영역에 **전체 모델**을 따로 만든다 →
   `workspace/cm/<name>.json`(+ `<name>.proof_ledger.json`, 실패 시 `<name>.buildlog`).
   `TF_SEED_JOBS`(기본 6)개씩 병렬로 돈다.
3. coverage 트리(`coverage.py --init`)와 가설(`gen_hypotheses.py`).

per-module 모델이 존재하는 이유는 4.1의 graph-only 저하다. graph-only 모델에는 dataflow도, 싱크
집합도, proof ledger도 없는데 그게 A와 B가 실제로 질의하는 것의 대부분이다. 그래서 큰 타깃의
보안 관련 영역마다 자기 모델을 갖고 역할은 `callgraph.py --model` / `proof_ledger.py --ledger`로
그쪽을 질의한다.

모듈 파일은 한 줄에 `name:path` 하나, 경로는 타깃 루트 기준 상대 경로다. `#` 주석과 빈 줄은 무시하고
이 버전에 없는 경로는 건너뛴다. 그래서 파일 하나가 릴리스를 넘어 계속 쓰인다. 모듈 파일 없이 돌리면
저장소 전체 색인과 coverage 트리, 가설만 만든다. 작은 타깃에는 그걸로 충분하다.

### 4.7 `hypothesize` — 서비스별 비즈니스 로직 가설

`gen_hypotheses.py`가 시드 단계에서 `workspace/HYPOTHESES.json`에 domain + universal + (상한을 둔)
CWE 파생 항목을 채운다. 이건 체크리스트지 파인딩이 아니다. 대부분 `target_endpoints`가 비어 있는데,
그게 아직 진짜 가설이 아니라는 표시다.

진짜 가설은 서비스별이고 시험 가능하다. "이 서비스는 사용자가 Y를 하는 X이므로, 엔드포인트 **E**의
동작 Z는 불변식 **R**을 깰 수 있고 공격자는 **G**를 얻는다." 실제 엔드포인트(E), 성립해야 할 규칙(R),
공격자 목표(G)를 전부 지목한다. "CWE-367 TOCTOU가 존재한다"는 가설이 아니라 렌즈다.

가설 모양:

```
{ "id":"H...", "source":"llm", "class":"...", "name":"short claim",
  "flow":"which business flow", "invariant":"rule R that must hold",
  "attacker_goal":"G the attacker achieves by breaking R",
  "target_endpoints":["POST /api/...", "..."],
  "why":"why this is plausible in THIS code", "check_how":"exact way to verify in code/live",
  "status":"open" }
```

프로듀서 A/B가 엔드포인트에 묶인 open 가설을 코드로 검증한다. 확인되면 파인딩을 쓰고 `hypothesis_id`를
걸고 가설을 `verified`로, 반증되면 한 줄 이유와 함께 `refuted`로 표시한다. `cwe_to_hypotheses.py`는
CWE XML(`CWE_XML` 환경 변수)을 카탈로그에 한 번만 병합한다.

---

## 5. 프로듀서 A — injection / data-flow (`vuln-track-a` 스킬)

**대상:** SQLi, command/code injection, XSS, SSRF, path traversal, file inclusion, 역직렬화, XXE,
SSTI, NoSQL, open redirect. 여기에 METHODOLOGY §2의 memory safety, info-leak, resource 클래스의
flow 모양까지.

트랙 A는 **flow 모양** 트랙이다(`defect_shape: "flow"`). 찾은 것이 사실 "검사가 없다"면
`defect_shape: "missing_control"`로 파일링하지, source→sink 이야기에 억지로 구겨 넣지 않는다. 트랙 B
것처럼 보인다고 버리지도 않는다.

**방법(sink-first, flow-aware):**

1. `callgraph.py --sinks` / `--callers`와 `<builtin-sink>` 엣지로 유한한 위험 싱크 집합을 열거한다.
2. 각 싱크마다 `--trace`로 파일을 넘어 **거꾸로** 따라가 공격자 제어 입력이 닿는지 본다.
3. 경로를 따라 새니타이즈/이스케이프를 판정한다. 자기 파일 안에서는 안전해 보이는 싱크가 몇 콜 떨어진
   곳에서 오염 데이터를 먹는 경우가 흔하다.
4. `write_finding.py`로 파인딩을 기록하거나(track A), 왜 그 싱크가 안전한지를 proof ledger에 증거와
   함께 남긴다.

A는 필수 패스 **P4**(장수 lifetime 스윕)와 **P5**(일곱 싱크 그룹 전부로의 taint)를 소유하고 B와 함께
**P6**(에러 경로 diff)과 **P7**(cross-scope/동시성)을 나눠 갖는다. 호출 그래프가 절대 보여주지 않는
소스 계열(post-free, bailout-orphaned, cross-scope, uninitialized reuse)이 여기 들어간다.

**도구 리드(파인딩 아님):** `run_semgrep.sh`가 OpenGrep(우선) 또는 Semgrep을 타깃에 돌리고
`semgrep_to_hints.py`를 통해 **LEADS**를 `workspace/hints/track-a-semgrep.{md,json}`에 쓴다. SAST
히트는 *볼 자리*지 파인딩이 아니다. 룰은 `vuln-track-a/rules/`(`injection.yaml`, `web.yaml`)에 있고
`fetch_rules.sh`가 커뮤니티 룰을 한 번 받아 둔다(온라인 필요).

`run_semgrep.sh`는 `--jobs 1 --max-target-bytes 500000 --timeout 20 --timeout-threshold 3`으로 돌고
`vendor/`, `node_modules/`, 미니파이 JS, `tests/`, `spec/`을 제외한다. 큰 저장소에서 Semgrep OSS 코어가
segfault하는 것을 피하려는 설정이다. 엔진이 없거나 죽어도 치명적이지 않다. 리드가 없다는 뜻이지 취약점이
없다는 뜻이 아니다.

**파인딩 임계선.** 후보 파인딩은 다섯 가지를 전부 만족해야 한다. 공격자 제어 소스, 엔트리 포인트에서
도달 가능한 실행 경로, 위험한 싱크, 빠졌거나 무력하거나 우회 가능한 완화, 구체적 보안 임팩트. 하나라도
없으면 파인딩을 쓰지 않고 proof ledger에 `safe`(이유 포함)나 `needs_reanalysis`로 남긴다. "위험한 함수가
존재한다"와 "이론적 우회"가 파인딩이 되는 걸 막는 선이다.

**완화를 그냥 믿지 않는다.** 소스가 싱크에 닿는데 중간에 새니타이저/인코더/allowlist/타입 검사/캐스트가
있으면 기본 질문은 "가드가 있으니 안전하다"가 아니라 "이 언어/런타임/프레임워크에서 이 가드를 우회할 수
있나"다. 스킬에 타입 저글링과 느슨한 비교, 인코딩과 이중 디코딩, 유니코드 정규화, 정규식 약점(앵커 누락,
멀티라인, ReDoS), 파서 불일치(SSRF allowlist vs HTTP 클라이언트, JSON 중복 키, CL/TE), 경로 정규화,
allowlist/이스케이프 구멍, 숫자 절단까지 카탈로그가 들어 있다. 안전하다고 판정할 때 쓰는 가드마다 어떤
우회 클래스를 왜 배제했는지 이름을 댄다.

**우선순위.** 리뷰 *순서*를 정하는 것이지 안전을 뜻하지 않는다. P0는 command/code injection, RCE로 가는
역직렬화와 SSTI, 실행 가능한 위치로의 임의 파일 쓰기와 업로드. P1은 SQLi, 인증 우회/데이터 접근을 주는
NoSQL injection, metadata/내부 admin/cloud/Redis/Docker socket으로 가는 SSRF, 파일 읽기·SSRF가 되는
XXE, 비밀이나 임의 파일 접근으로 가는 path traversal. P2는 stored XSS와 admin 대상 XSS, OAuth/로그인
흐름의 open redirect. P3는 익스플로잇이 제한적인 reflected XSS 등. XSS를 자동으로 강등하지 않는다. 누가
어떤 권한으로 실행하고 그다음에 무엇이 오는지가 순위를 정한다.

---

## 6. 프로듀서 B — logic / access-control (`vuln-track-b` 스킬)

**대상:** SAST가 못 보는 것들. IDOR/BOLA, 빠진 인가, 권한 상승, 인증/세션 우회, 비즈니스 로직 결함
(단계 건너뛰기, 가격/수량 조작, mass assignment, 레이스). 여기에 METHODOLOGY §2에서 다른 주인이 없는
crypto, 설정, 공급망의 부재 모양과 TOCTOU의 로직/상태 절반까지.

트랙 B는 **부재 모양** 트랙이다(`defect_shape: "missing_control"`). 데이터 흐름은 멀쩡한데 *규칙*이
틀렸다. 필요한 검사가 도달 가능한 경로에 없어서 사용자가 닿으면 안 되는 리소스나 동작에 닿는다. 도구는
무엇이 허용'돼야' 하는지 모르므로 스크립트는 구조적 시드만 주고 추론은 역할이 한다.

B는 필수 패스 **P1**(entry × privilege 맵), **P2**(모든 privileged op에 대한 가드 감사), **P3**(불변식
위반 스윕)을 소유하고 A와 함께 P6, P7을 나눠 갖는다.

**방법(엔트리 포인트에서 리소스까지의 경로):**

1. `build_authz_matrix.py`가 결정적 **시드**를 만든다. 라우트/동작 × 역할 매트릭스에
   `expected_access`는 `?`로 두고 결정적 red flag와 후보 목록을 붙여 `workspace/_authz_matrix.json`에
   쓴다. `comprehension`이 얇으면 `structural.entry_points`로 fallback하는데 그러면 auth/role 필드가
   `unknown`이 된다. unknown은 안전이 아니라 읽어서 증명할 일감이다.
2. 역할이 라우트마다 `expected_access`를 채운다. **제품 정책을 지어내지 않는다.** 라우트 이름과
   admin/user 네임스페이스, 기존 미들웨어 패턴, policy/ability 클래스, 비슷한 라우트의 역할 검사,
   테스트, API 문서, 프런트엔드 동작, 도메인 불변식, 객체 소유권/테넌트 관계 같은 구체적 증거에서
   끌어낸다. 정말 모호하면 `unknown`으로 두고 그 라우트를 `needs_reanalysis`로 표시하지, 파인딩을 쓰지
   않는다. 놀라운 권한이 곧 취약점은 아니다. 구체적 정책이나 보안 불변식을 위반한다는 것을 보여야 한다.
3. 라우트마다 `callgraph.py --forward`로 `handler → service → repository/object-load`를 따라가면서
   **체인 전체에** 묻는다. authn 검사가 있나, 역할/권한 검사가 있나, 요청된 객체 id에 대한
   **소유권/테넌트** 검사가 있나.
4. 라우트에서 도달 가능하고 경로에 소유권 검사가 **없는** `findById/load/getByID`는 IDOR다. 상태를
   바꾸는 동작에 역할 검사가 없으면 broken authz다.
5. `comprehension.user_journeys`를 걸으며 단계 건너뛰기(CWE-841), 서버가 믿는 클라이언트 제어 상태
   (CWE-915), 레이스(CWE-362)를 본다.
6. 트랙 B로 기록하거나, 코드로도 라이브 테스트로도 확정 못 하면 이유와 함께 `needs_reanalysis`로 둔다.

shape B 파인딩에서 `sink`는 privileged op 자신의 위치(스코프 없는 로드, 상태 변경, capability 없는
동작)이고 `source`는 공격자가 고른 키나 아이덴티티가 들어오는 지점이다. `missing_control`이 실제 증거를
나른다. 어떤 검사가, 어디 앉아야 하고 어떤 경로가 그것 없이 연산에 닿으며 누가 그 경로를 걸을 수 있는지.

**함수가 아니라 흐름을 심문한다.** 로직/authz 버그는 함수 하나를 위에서 아래로 읽어서는 잘 안 보인다.
그 함수가 어떻게 *도달되고 조합되는지*에 있다. 같은 서비스 메서드가 API 엔드포인트, GraphQL 리졸버,
웹훅, 큐 워커, CLI/admin 태스크, 내부 RPC, 배치 임포트에서도 재검사 없이 불리지 않는지 privileged op의
모든 호출자를 열거한다. 가드가 엉뚱한 레이어에 있는 경우(컨트롤러에서 검사하는데 서비스가 다른 데서 직접
불린다, 읽기에서는 소유권을 확인하고 뒤따르는 쓰기에서는 안 한다), 단계별로는 인가되는데 순서가 불변식을
깨는 경우(TOCTOU, 중간 단계 리플레이, 1단계에서 검증하고 3단계에서 믿는 값, 멱등성/리플레이), 상태·역할
전이로 검사를 건너뛰는 경우를 본다. 가드가 제대로 있다고 판정하면 정확히 어떤 검사가 어느 레이어에 있는지
이름을 대고 **모든** 호출자가 그 레이어를 지나는지 확인한다. 라우트 하나만 보고 내린 authz "safe" 판정은
미완성이다.

---

## 7. 컨슈머 C — convergence (`convergence` 스킬)

C는 A/B가 생산하는 동안 계속 돈다. 루프는 이렇다.

### 7.1 교차 검증 (`cross_validate.sh`, `correlate.py`)

```bash
cross_validate.sh targets/<app> [language]
```

항상 **CodeQL을 먼저** 쓴다(가장 깊은 절차 간/파일 간 taint). CodeQL이 없거나 실패하면 OpenGrep/Semgrep으로
떨어지므로 교차 검증이 조용히 건너뛰어지는 일은 없다. `ENGINE=opengrep`으로 강제할 수 있다. 언어는 인자로
주거나 `CODE_MODEL.json`의 `target.languages`에서 추론한다. **CodeQL에는 PHP가 없으므로** PHP 타깃은
데이터베이스 생성이 실패하면서 자동으로 OpenGrep으로 떨어진다.

라이선스 주의: CodeQL은 OSI 오픈소스/연구용으로만 무료다. 비공개 코드에는 GitHub Advanced Security가
필요하다.

이어서 `correlate.py`가 엔진 출력(SARIF 또는 JSON)을 파인딩에 매칭해서, 엔진도 같은 싱크를 지적한 후보를
`status: cross_validated`로 올리고 history 항목을 남긴다. 수작업 매칭은 없다. 트랙 B의 로직 파인딩은 이
단계를 건너뛴다. 재현이 동작을 증명하고 공식/벤더 게이트가 제품 취약점인지 결정한다.

### 7.2 동적 재현 (`probe.py`, `browser_probe.py`, `canary.py`)

라이브 URL이 주어졌을 때만 수행한다. 재현은 **warm target env**에만 쏜다. 세션당 한 번 띄우고 외부
호스트는 절대 건드리지 않는다.

`probe.py`는 표준 라이브러리만 쓰는 최소 HTTP 프로브다. 요청 하나를 보내고 status/ms/len/snippet을
JSON으로 돌려준다.

```bash
probe.py -X GET  "http://localhost:3000/api/orders/2" -H "Authorization: Bearer <jwtA>"
probe.py -X POST "http://localhost:3000/login" -d '{"u":"a"}' -H "Content-Type: application/json"
```

플래그는 `-X/--method`, `-H/--header`(반복 가능), `-d/--data`, `--timeout`뿐이다. 세션은 직접 관리한다.
로그인 라우트, CSRF 흐름, 세션 포맷은 타깃 코드에서 알아내고 받은 쿠키를 다음 요청의 `-H "Cookie: ..."`로
넘긴다. (`convergence` 스킬 본문과 `browser_probe.py`의 도움말은 아직 `probe.py`가 쓰는 쿠키 jar
(`--jar FILE`)를 전제로 쓰여 있는데, 현재 `probe.py`에는 그 플래그가 없다. 스킬 쪽 설명이 코드보다
앞서 있다.)

- **트랙 A 재현:** 만든 페이로드를 쏘고 싱크가 터지는지 확인한다(에러, 반사된 페이로드, 시간 지연,
  out-of-band 히트).
- **트랙 B / IDOR 재현:** 두 계정을 각각 로그인해 서로 다른 세션을 들고 한 사용자의 객체를 **다른
  사용자의** 세션으로 요청한다. `200`과 함께 피해자 데이터가 돌아오면 동작이 재현된 것이다. 권한 상승은
  저권한 세션으로 admin 전용 동작을 친다. `accounts.json`에 **일반 사용자 2명 이상**이 필요한 이유가
  이것이다. admin 하나로는 교차 사용자 접근을 증명하지 못한다.

`browser_probe.py`는 **XSS를 실행으로** 증명한다(Playwright 헤드리스 Chromium). HTTP 본문에 반사되는
것은 증명이 아니다. 페이로드 URL로 이동한 뒤 JS 다이얼로그가 뜨거나 주입된 마커(`window.__tf_xss`)가
실제로 돌았을 때만 `executed:true`를 보고한다.

```bash
browser_probe.py --url "http://host/search?q=<payload>"
browser_probe.py --url "http://host/profile" --jar alice.jar          # authed/stored
browser_probe.py --url "http://host/p" --wait 1500 --timeout 15000
```

`--jar`는 MozillaCookieJar 포맷 파일을 읽어 브라우저 컨텍스트에 쿠키를 주입하므로 stored/인증된 XSS도
재현할 수 있다. 출력은 `{executed, signals[], dialogs[], console[], errors[], final_url}`이고
실행됐으면 종료 코드 0이라 셸에서 분기할 수 있다. 설치는 한 번:
`pip install playwright && python3 -m playwright install chromium`.

`canary.py`는 SSRF/블라인드 버그용 **out-of-band 서버**다. `--url`이 주어지거나 `TF_CANARY=1`일 때
`audit.sh`가 띄운다(기본 `127.0.0.1:9111`, 로그는 `workspace/_canary.log`).

```bash
canary.py serve --port 9111 --log workspace/_canary.log   # listener (audit.sh starts this)
canary.py url   <token> --host H --port N                 # the URL to embed in a payload
canary.py check <token>                                   # HIT = SSRF confirmed out-of-band
```

취약한 파라미터를 통해 타깃이 `http://<canary>/<token>`을 가져오게 만든 뒤 `canary.py check <token>`을
한다. HIT이면 SSRF가 증명된다. 콜백이 불가능한 내부/블라인드 SSRF는 내부 호스트(127.0.0.1:<port>,
169.254.169.254) 대상 응답·타이밍 차이로 판정하고 그것도 안 되면 이유와 함께 `needs_reanalysis`로
남긴다. SSRF를 시도조차 안 한 채로 두지 않는다.

**PoC는 항상 붙인다.** 재현되는 정확한 요청(메서드, URL, 헤더, 페이로드가 전부 든 복붙 가능한 줄)을
`repro.poc`에, 결정적 응답 증거를 `repro.response`에 넣는다. IDOR이면 두 아이덴티티의 요청을 모두 담는다.
PoC가 없으면 재현이 아니다. 결과에 따라 `reproduced`, `false_positive`, 또는 (모호하면) `needs_reanalysis`로
상태를 갱신한다.

### 7.3 공식/벤더 제품 경계 리뷰 (필수)

모든 `reproduced` 파인딩은 제품 취약점이라 불리기 전에 1차 벤더 자료와 대조해야 한다. 재현된 정확한 동작,
컴포넌트/버전, 전제 조건, 기본/지원 설정, 문서화된 보안 경계, 싱크 소유권을 비교한다. 1차 자료는 공식 문서와
보안 가이드, API 계약, 기본 템플릿/샘플, 버전이 박힌 소스 주석과 테스트, 어드바이저리, 릴리스 노트, 패치,
벤더 소유 이슈/디스커션이다. Microsoft 타깃이면 Microsoft Learn/MSRC와 Microsoft 소유 소스가 1차다.
서드파티 연구는 검색을 이끌 수는 있어도 1차 증거를 대신하지 못한다.

비교할 때 키워드가 아니라 **정확한 동작과 전제 조건**을 본다.

- 정확한 제품/컴포넌트/버전과 그것이 지원 대상인지
- 기본/벤더 생성 설정인지, 애플리케이션이 작성한 안전하지 않은 설정인지
- 문서화된 보안 경계, API 계약, 미들웨어 순서, 명시된 호출자 의무
- 결정적 보안 싱크가 제품의 것인지, PoC 앱이 덧붙인 것인지
- 의도된 동작을 보여주는 버전 박힌 소스 테스트, 패치, 릴리스 노트, 어드바이저리

성공한 요청, 인증 우회 관찰, 크래시, 프로세스 생성 그 자체는 벤더 제품 취약점의 증명이 아니다. 공식 문서가
바로 그 미들웨어 순서가 위험하다고 경고하고 안전한 순서를 제시한다면 결과는 `documented_hazard`다. 설정된
샘플을 새 프레임워크 취약점이라 부르지 않는다. 반대로 문서가 없다는 것만으로 증명이 되지도 않는다. 재현된
동작이 위반하는 지원 보안 불변식을 지목해야 한다.

`official_review{checked,verdict,sources,rationale,product_version,default_configuration}`를
`write_finding.py`로 쓴다. `sources`에는 1차 공식/벤더 문서, 보안 가이드/어드바이저리, 릴리스/패치 자료,
또는 벤더 소유 저장소 이슈/디스커션의 공개 HTTPS URL이 최소 하나 있어야 한다. 로컬/버전 소스 경로는 보조
자료일 뿐이고 GitHub `blob`/`tree`/raw 소스 URL도 그것만으로는 이 게이트를 통과하지 못한다. `rationale`은
공식 자료와 PoC를 직접 비교하면서 어떤 보안 불변식이 깨졌는지, 또는 왜 제품 버그가 아닌지를 말해야 한다.

판정 매핑:

- `product_vulnerability` 또는 `known_vulnerability` → 상태 `confirmed`
- `documented_hazard`, `expected_behavior`, `application_misconfiguration`, `unsupported_scenario`
  → 상태 `not_product_vulnerability`
- `inconclusive` → `reproduced`로 남기고 무슨 증거가 없는지 기록한다. 보고 대상도, 0-day 랭킹 대상도,
  D로 넘길 대상도 아니다.

### 7.4 증거 계약 (`confirmed`에서 강제)

재현과 공식 리뷰는 "동작이 실재하고 벤더의 것"이라고 말한다. 증거 계약(METHODOLOGY §7)은 읽는 사람에게
"그 동작이 실제로 무엇인지"를 말한다. `confirmed`로 올리는 바로 그 `--update`에서 함께 채운다.
`write_finding.py`가 없으면 거부한다.

- `defect_shape` — `flow`(세 다리 전부) 또는 `missing_control`(+
  `missing_control{control,expected_at,unguarded_path,actor}`). 프로듀서가 비워 뒀다면 모양을 한 번도
  정하지 않았다는 뜻이니 파인딩의 이야기가 성립하는지 다시 본다.
- `reachability{entry_point,min_privilege,pre_auth,call_chain}` — 누가, 어떤 권한으로 트리거하는지
  체인으로 증명한다. 프로듀서가 pre-auth라고 주장했으면 인증 없는 요청으로 확인하고 실제로 재현한
  수준으로 `min_privilege`를 내린다.
- `preconditions{default_configuration,required_settings}` — 기본/벤더 출하 설정에서 재현했을 때만
  true다. 플러그인, 플래그, 비기본 설정을 켜야 했다면 그렇게 적고 목록을 남긴다.
  `official_review.default_configuration`과 같은 판단이고 둘은 일치해야 한다.
- `primitive{kinds,escalation_ceiling,ruled_out}` — 증명한 능력과 정직한 한계. *시도했는데 실패한* 상승은
  이유와 함께 `ruled_out`에 넣는다. 시도조차 안 한 것은 배제가 아니고 주장하지 않는다. D가 나중에 증거와
  함께 천장을 올린다.
- `repro{reliability,instrumentation_only,stock_replay}` — 얼마나 반복 가능한지(레이스와 힙 상태 버그에는
  필수), 그리고 그 관찰이 새니타이저·디버그 assertion·패치 빌드·진단 프로브 아래에서만 존재한 적이 있는지.
  그런 관찰은 `stock_replay`가 정확한 stock 빌드 실행을 기록하기 전까지 **리드**다.

과대 포장은 보고 결함이고 한계 없는 주장은 벤더가 진짜 버그를 닫게 만드는 가장 쉬운 길이다.
"Read-only, self-owned objects only"가 모호한 "may allow privilege escalation"보다 나은 파인딩이다.

### 7.5 공개 이력 리뷰 — known vs novel (confirmed 제품 취약점만)

공식 리뷰를 통과해 `confirmed`가 된 뒤에야 이미 알려진 것인지 새 발견인지 가린다. 정확히 일치하는 공개
이력 사다리를 전부 탄다.

1. 영향받는 경로와 정확한 패치 지문으로 소스 이력을 검색한다(`git log -S'<literal>' -- <path>`,
   `git log -G'<semantic-regex>' -- <path>`, 벤더 커밋 히스토리/API, blame). 지문은 증명에서 끌어낸다.
   영향 경로, 클래스/메서드, 헬퍼나 검증 플래그, 거부 사유/에러 문자열, 특징적 리터럴, 깨진 프로토콜 불변식.
2. 테스트한 버전을 upstream main 및 지원 릴리스 브랜치와 비교한다. 일치하는 diff를 들여다보고 연결된 이슈,
   PR, cherry-pick, servicing PR, 백포트를 따라간다.
3. 정규 벤더 저장소의 **open/closed 이슈**와 **open/merged PR**을 정확한 심볼, 파일명, 검증 플래그, 에러
   문자열, 프로토콜 용어, 의미적 패러프레이즈로 검색한다. 제안할 취약점 제목만 검색하지 않는다.
4. 벤더 어드바이저리, 보안 어드바이저리, CVE, 릴리스 노트, servicing 노트, 체인지로그를 본다. 이건 마지막
   범주지 공개 이력 리뷰 전체가 아니다.

증거는 `disclosure.public_history`에 저장한다. 정규 `upstream_repository`, 최소 두 개의 `exact_anchors`,
`source_history`, `vendor_issues_prs`, `advisories_releases`, 그리고 정확한 `head_or_release_comparison`.
그다음 `disclosure`를 정한다.

- `known` — 같은 근본 원인에 대응하는 공개 벤더 이슈, PR, 커밋, 패치, 테스트, 어드바이저리, CVE, 릴리스
  노트, 체인지로그가 있다. 보안 라벨이 없어도 공개 소스 수정이 있으면 known이다.
- `novel` — 사다리를 전부 탔는데 정확한 일치가 없고 구조화된 증거가 완전하다.
- `inconclusive` — 판단 불가.

writer가 증거 없는 `novel`을 거부하고 triage와 대시보드는 공개 이력 게이트가 불완전하면 `disclosure.status`가
`novel`이라고만 적힌 과거 파인딩까지 포함해 potential 0-day 라벨을 숨긴다. 이 조사를 raw candidate에 쓰지
않는다.

### 7.6 PoC + 취약점별 리포트 (`emit_poc.py`)

공식 리뷰 판정이 `product_vulnerability`나 `known_vulnerability`인 `confirmed` 파인딩마다 에이전트가
`requests`로 `poc.py`를 작성한다. 버그에 맞춘다. pre-auth면 로그인 단계가 없고 다단계면 필요한 만큼
요청을 보내고 PASS/FAIL을 명확히 출력한다. 고정된 login→exploit 템플릿을 가정하지 않는다. 전체 소스를
`repro.poc_script`에 넣고 `emit_poc.py`를 돌리면 취약점마다 폴더가 생긴다.

```
workspace/report/<id>/poc.py        # saved verbatim; re-run with: python3 poc.py
workspace/report/<id>/finding.md    # that vuln's individual report
```

`emit_poc.py`는 PoC 단계를 지어내거나 파싱하지 않는다. 에이전트 스크립트를 그대로 저장한다. `poc_script`가
없으면 그 사실을 적은 stub `poc.py`를 써서 폴더가 비지 않게 한다. 취약점 하나당 폴더 하나이고 병합하지
않는다.

### 7.7 Triage + 리포트 (`triage.py`, `queue.py`)

```bash
triage.py [--findings workspace/findings] [--out workspace/report/report.md]
```

모든 파인딩을 읽어 `correlation_id`로 중복을 제거한 뒤 severity × confidence(status)로 순위를 매긴다.
여기에 CWE → OWASP Top 10 매핑을 붙여 `workspace/report/report.md`를 쓴다. `false_positive`와
`not_product_vulnerability`는 랭킹에서 빠진다. 공식 게이트를 아직 통과하지 못한 채 `confirmed`라고만
적힌 과거 파인딩은 `reproduced` 수준의 confidence로 취급한다.

리포트 구성:

- 상태별 카운트와, 공식 리뷰 대기 / 공개 이력 리뷰 대기 건수(raw와 고유 근본 원인 각각)
- `## Official/vendor review pending` — 재현은 됐지만 판정이 안 난 것들
- `## Public-history/disclosure review pending` — confirmed인데 공개 이력 사다리가 미완인 것들
- `## ⚠️ Potential 0-day (officially reviewed product vulnerabilities)` — 공식 리뷰와 공개 이력 게이트를
  둘 다 통과한 것만
- `## 💥 Weaponized / chained exploits` — `exploit.depth`가 `chained`/`weaponized`인 것
- `| # | sev | status | official review | disclosure | class | CWE | OWASP | location | dups |` 랭킹 표
- 파인딩별 상세(PoC 명령, 응답 증거, 공식 리뷰와 disclosure 상태)

읽을 수 없는 파인딩 파일은 조용히 버리지 않고 경고로 드러낸다.

`queue.py`는 기계가 읽는 큐 뷰다.

```bash
queue.py --counts       # findings by status
queue.py --pending      # count still needing convergence work
queue.py --reanalysis   # ones routed back to E
queue.py --findings DIR # non-default findings dir
```

### 7.8 라이브 대시보드 (`dashboard.py`)

tmux의 마지막 패널이다. 약 3초마다 `triage.py`와 `emit_poc.py`를 조용히 돌려 `report.md`와 취약점별
폴더가 묵지 않게 하고 커버리지 바, 상태/클래스별 파인딩 수, 공식 리뷰와 공개 이력 게이트를 모두 통과한
**potential 0-day 카운터**, 최근 히트, 경과 시간을 렌더링한다.

### 7.9 보고 전 자체 점검

파인딩이 랭킹 리포트에 들어가기 전, 그리고 마지막 triage 전에 C가 METHODOLOGY §8 체크리스트(§2.11)를
돌린다. "아니오"가 하나라도 있으면 리포트에 단서를 다는 대신 `needs_reanalysis`로 되돌린다.

---

## 8. D — exploitation (critical 파인딩 무기화)

C는 버그가 진짜임을 증명한다. **D**는 그 증명을 완전히 이해된 익스플로잇으로 바꾼다. 대상은 진짜 critical
클래스뿐이다(rce, command-injection, sql-injection, auth-bypass, deserialization, ssrf-to-internal).
루프는 이렇다.

1. **고른다.** `findings/*.json`에서 `status`가 `confirmed`이고 `official_review.verdict`가
   `product_vulnerability` 또는 `known_vulnerability`이며 `vuln_class`가 critical이고 `exploit.depth`가
   없거나 `shallow`인 것을 집는다. 나머지는 건너뛴다. severity 높은 것부터.
2. **깊이 판다.** 모든 단계를 라이브 타깃에서(라이브 URL이 없으면 인가된 랩의 로컬 빌드에서) 검증한다.
   - **체이닝과 상승**: 증명된 프리미티브에서 실제 최고 임팩트까지. blind SQLi → boolean/time exfil,
     토큰 하나로 제한된 command injection → 페이로드 파일을 심고 경로로 호출, SSRF → `canary.py`를 통한
     클라우드 메타데이터/내부 서비스, auth-bypass → admin 전용 동작 도달.
   - **완화 무력화**: 새니타이저/이스케이프/쿼팅/WAF가 뻔한 페이로드를 막으면 *정확히* 어떤 바이트와
     메타문자가 살아남는지 알아내고 실제로 실행되는 우회를 찾는다. 손짓으로 넘어가지 않는다.
3. **정직하게 기록한다.** 파인딩의 **`exploit`** 객체에
   `{depth: shallow|chained|weaponized, primitive, max_impact, steps[], mitigations_bypassed[],
   constraints[], working_poc, oob_evidence}`를 쓴다. 임팩트에 한계가 있으면 그 한계를 `constraints`에
   그대로 넣는다. 정확한 "제한적" 결과가 과장된 결과보다 낫다. `write_finding.py`는 보고 가능한 공식 리뷰가
   없는 파인딩에 `exploit`을 추가하거나 바꾸는 것을 거부한다.
4. **물리적으로 남긴다.** `workspace/report/<id>/exploit.py`(독립 실행, PASS와 수집된 증거를 출력)를 C의
   `poc.py`와 별도로 쓴다. `triage.py`가 chained/weaponized 파인딩을 전용 섹션에 올리고 대시보드가 카운터를
   보여준다.

**왜 별도 역할인가.** 재현(C)과 무기화(D)는 사고방식과 시간 예산이 다르다. C는 모든 파인딩에 걸쳐 큐를 계속
움직여야 하고 D는 몇 개를 깊게 판다. 쪼개 두면 C가 어려운 익스플로잇 하나에 멈춰 있는 동안 뒤늦은 파인딩이
쌓이는 일이 없다. D는 자기가 지목받은 타깃에만 묶인다. 소유했거나 테스트 권한이 있는 자산을 대상으로
무기화하지, 임의의 호스트를 치지 않는다.

---

## 9. E — reanalysis (`needs_reanalysis` 전담)

E는 상태가 `needs_reanalysis`인 파인딩만 폴링한다. `convergence` 스킬을 읽고 파인딩의 트랙에 따라
`vuln-track-a`나 `vuln-track-b`를 추가로 읽는다.

항목마다 C의 정확한 관찰과 재시도 이력을 읽고 빠진 전제나 실패한 재현 단계를 짚고 해당 코드 경로를 다시
보고 해결에 필요한 가장 작은 인가된 라이브 테스트를 수행한다. 특히 빠뜨린 대체 엔트리 포인트, 인증 상태
가정, 파서 차이, 환경 전제 조건, 그리고 이 문제를 pre-auth 또는 authenticated RCE로 바꿀 수 있는 체인
고리를 찾는다.

진짜 새 증거가 나오면 C가 다시 보도록 `candidate`나 `cross_validated`로 돌려주고 결정적 라이브 증명을
잡았으면 `reproduced`로 올린다. 반증됐거나 재시도를 새 증거 없이 소진했으면 `false_positive`로 닫는다.
재시도 횟수는 `write_finding.py`가 `needs_reanalysis` 갱신마다 올리는 `reanalysis_count`로 센다. **바뀐 것 없이 되돌리지 않는다.** 모든 갱신은
`write_finding.py`로만 하고 끝나면 다시 폴링한다.

A와 B는 이미 `needs_reanalysis`로 표시된 파인딩을 건드리지 않는다. 그 상태의 소유자는 E 하나다. C가 깃발을
올리고 E가 진단한다.

---

## 10. 공유 writer와 노트 (`_shared/`)

### 10.1 `write_finding.py`

파인딩을 만들고 갱신하는 유일한 경로다. A, B, C, D, E가 전부 이걸 쓴다. **file-lock**(`fcntl`)이 걸려
있고 이력에 **append-only**라 다섯 세션이 같은 파일을 망가뜨리지 않는다.

```bash
echo '<partial finding json>' | write_finding.py
write_finding.py --file finding.json
write_finding.py --update <id> --file patch.json   # merge an update (status, repro, disclosure...)
write_finding.py --out DIR --schema schemas/finding.schema.json
```

기계적 필드(`id`, 타임스탬프, `history`, 기본값)는 writer가 채우고 스키마 검증은
`schemas/finding.schema.json`으로 한다(jsonschema가 없으면 경고하고 건너뛴다). `defect_shape`가 없으면
경고를 출력한다. 후보 단계에서는 치명적이지 않지만 종단 게이트가 요구하고 모양을 일찍 정하는 것이 shape B
버그가 억지 source→sink 이야기에 구겨 넣어지는 걸 막는다.

**종단 게이트.** 상태를 `confirmed`나 `not_product_vulnerability`로 올리려면 다음이 전부 필요하다.

1. 성공한 동적 재현 — `repro.attempted`와 `repro.success`가 true, `repro.poc`와 `repro.response`가 비어
   있지 않을 것.
2. 완성된 `official_review` — `checked: true`, 최소 하나의 **1차 공식/벤더 공개 HTTPS URL**
   (GitHub `blob`/`tree`/raw 링크만으로는 거부된다), 20자 이상의 `rationale`, 정확한 `product_version`,
   그리고 `default_configuration` 값(true/false/null).
3. 상태와 일치하는 `verdict` — `confirmed`에는 `product_vulnerability`/`known_vulnerability`,
   `not_product_vulnerability`에는 `documented_hazard`/`expected_behavior`/
   `application_misconfiguration`/`unsupported_scenario`.

`confirmed`에는 증거 계약도 함께 강제한다. `defect_shape`(그리고 `missing_control`이면 `control`과
`unguarded_path`), `reachability{entry_point,min_privilege,pre_auth}`,
`preconditions.default_configuration`(false면 `required_settings`까지), 10자 이상의
`primitive.escalation_ceiling`, 그리고 `repro.instrumentation_only`가 true면 `repro.stock_replay`.

`disclosure.status=novel`은 추가로 `official_review.verdict=product_vulnerability`와 완전한
`public_history` 레코드(정규 저장소 URL, exact anchor 2개 이상, source history, vendor issues/PRs,
advisories/releases, 20자 이상의 head/release 비교)를 요구한다. `known`은 정확한 공개 벤더 참조 URL을
요구한다.

각 거부 메시지는 무엇이 빠졌는지 그대로 말해 준다. 증거가 눈앞에 있을 때 채우는 쪽이 싸다.

### 10.2 `_shared/leads.py` — 딥 분석 노트

`write_finding.py`가 취약점을 기록한다면 `leads.py`는 그것이 만들어지는 **원재료**를 기록한다. 한 번
패스라면 버려질 중간 관찰들이다. 역시 file-lock이라 병렬 세션이 안전하게 덧붙인다.

```bash
echo '{"kind":"lead","where":{"file":"x.js","line":42,"symbol":"parseModel"},
       "observation":"walks value[path[i]] from user-split string, no hasOwnProperty",
       "why_interesting":"attacker-controlled property walk -> possible prototype access",
       "enables":["arbitrary-member-walk"]}' | leads.py add
echo '{"kind":"primitive","observation":"can reach Function constructor",
       "enables":["code-exec"]}' | leads.py add
leads.py note <target> --set "understood X; hold capability Y; next try Z"
leads.py note <target>                           # read the running note
leads.py list [--kind lead|primitive]
leads.py open                                    # what's still combinable
leads.py link <id> <id> ...                      # record a candidate chain
leads.py update <id> --status open|combined|dead|promoted --reason "..."
```

항목은 세 종류다. **lead**(아직 버그는 아닌 흥미로운 관찰과 그것이 `enables`하는 것), **primitive**(확인된
능력), **note**(타깃 하나에 대한 진행 상태. 재시작을 넘겨 살아남아서 나중 세션이 처음부터 다시 시작하지
않고 파던 데를 이어 판다). `link`가 리드들을 후보 체인으로 묶는다. 데이터는 `workspace/leads.json`과
`workspace/_analysis_notes.json`에 산다. 리드는 의도적으로 파인딩이 *아니다*. 취약점을 기록하는 것은
`write_finding.py`뿐이고 그 파인딩은 승격된 여러 리드로 만들어질 수 있다.

### 10.3 `_shared/budget_guard.py`

supervisor가 역할 세션을 재시작할 때마다 한 번 부른다. `workspace/_log_*.txt`에서 흔한 토큰 사용량 표식을
긁어 누적값을 내고 `TF_TOKEN_BUDGET`을 넘으면 `workspace/_stop`을 touch한다. 표식을 하나도 못 찾으면 0을
보고하고 절대 멈추지 않는다(fail-open). 측정할 수 없는 예산이 작업을 죽여서는 안 된다. 기본
`TF_TOKEN_BUDGET=0`은 가드를 끈다.

```bash
budget_guard.py --check     # exit 0 always; touches _stop if over budget; prints usage
budget_guard.py --report    # just print cumulative tokens, no side effects
```

---

## 11. 오케스트레이션 (`seed.sh`, `audit.sh`, `start.sh`, `campaigns/`, `test.sh`)

### 11.1 백엔드

`TF_BACKEND`가 역할 세션을 무엇으로 돌릴지 고른다.

- `codex`(기본) — `codex exec --sandbox workspace-write
  --config sandbox_workspace_write.network_access=true --config web_search=live
  --model gpt-6-sol --config model_reasoning_effort=xhigh`
- `claude` — `claude -p --output-format stream-json --verbose --dangerously-skip-permissions
  --model ${TF_MODEL:-claude-opus-5}`

백엔드 설정은 기본값만 공급한다. 명시적인 `CODEX_CMD`나 역할별 `CODEX_CMD_A` … `CODEX_CMD_E`가 여전히
이긴다. 그래서 D에만 더 센 모델을 붙이는 식의 혼합 캠페인이 그대로 동작하고 `start.sh`의 패널 제목이
역할마다 실제로 도는 모델을 표시한다.

`.codex/agents/*.toml`에 다섯 역할 정의가 남아 있지만 현재 `audit.sh`는 그것을 읽지 않는다. 미션 텍스트는
`audit.sh` 안에 인라인으로 들어 있다. TOML을 고쳐도 실행은 바뀌지 않는다.

### 11.2 `seed.sh` — 시드

```bash
./seed.sh targets/<app> [campaigns/<name>.modules]
```

§4.6 참조. 체크아웃마다 한 번 돌리고 이후 실행은 `TF_REUSE_SEED=1`로 재사용한다.

### 11.3 `audit.sh` — 엔진

```bash
./audit.sh [-u|--url URL] [--accounts FILE] targets/<app>
```

순서:

1. 타깃 검증. `targets/` 아래의 실재 경로여야 하고 아니면 거부한다.
2. `.env`를 로드하되 호출자가 명시한 `SSRF_HOST`/`SSRF_PORT` override는 보존한다. 평가가 자기 canary를
   인가된 로컬 엔드포인트에 고정해 둘 수 있게 하려는 것이다.
3. **시드.** `TF_REUSE_SEED=1`이면 `CODE_MODEL.json`, `coverage.json`, `HYPOTHESES.json`이 존재하고
   타깃이 일치하는지 검증만 하고 재사용한다(불일치면 즉시 실패). 아니면 `build_code_model.sh`,
   `coverage.py --init`, `gen_hypotheses.py`를 돌린다(`CWE_XML`이 있으면 CWE 병합도 한 번).
4. **라이브 컨텍스트.** `--url`이 있으면 계정 파일을 `workspace/_accounts.json`으로 복사하고 canary를
   띄우고 "이 URL만 인가됐다"는 컨텍스트를 만든다. `--url`이 없고 `TF_CANARY=1`이면 라이브 서비스 없이
   canary만 띄운다. 로컬 빌드 사본을 랩에서 돌리는 타깃이 out-of-band 오라클을 필요로 할 때 쓰는 모드다.
   캠페인 스크립트가 리스너를 손수 만들면 `audit.sh`가 내리는 것과 어긋나기 때문에 여기로 들여왔다.
   둘 다 아니면 static-only 모드다. canary는 멱등적이다. 다른 세션이 이미 듣고 있으면 재사용한다.
   `TAINTFORGE_DYNAMIC_CONTEXT`로 이 컨텍스트 블록 전체를 대체할 수 있다.
5. **공통 컨텍스트 + 역할별 미션.** 모든 역할이 같은 `COMMON_CONTEXT`를 받는다. `AGENTS.md`,
   `METHODOLOGY.md`, 자기 스킬을 전부 읽을 것, 서브에이전트에 위임하지 말 것, 결함 모양을 먼저 정할 것,
   아이덴티티 상태·저장된 값·post-free와 bailout 상태·cross-scope 상태·순서를 공격자 소스로 다룰 것,
   자기가 소유한 필수 패스를 돌릴 것, 1차 목표는 pre-auth RCE이고 그다음이 authenticated RCE일 것,
   `targets/`는 읽기 전용일 것, 인가된 라이브 타깃과 로컬 canary 외에는 접속하지 말 것,
   `workspace/_stop`이 나타날 때까지 계속할 것, 빈 큐는 절대 완료가 아닐 것.
   여기에 `TAINTFORGE_EXTRA_CONTEXT`(캠페인이 주는 타깃별 사실)가 붙는다.
6. **다섯 supervisor 기동.**
   ```
   supervise(){ ( while no _stop and now < DEADLINE; do
                    $rolecmd "$mission" >> "$logfile" 2>&1 </dev/null &
                    wait; budget_guard.py --check; sleep 5
                 done ) </dev/null >/dev/null 2>&1 & }
   ```
   역할마다 로그가 하나씩 생긴다. `workspace/_log_A.txt` … `_log_E.txt`(canary를 띄웠으면
   `_log_canary.txt`도). 세션마다 헤더 줄이 로그에 찍혀서 재시작 횟수와 쓰인 명령이 보인다. fd는 전부
   분리돼 있어서 백그라운드 supervisor가 부모 셸을 붙잡지 않는다.
7. supervisor PID와 canary PID를 `workspace/_pids`에 쓴다.
8. `SPAWN_ONLY=1`이면 즉시 리턴한다(`start.sh`가 쓴다). 아니면 supervisor를 `wait`하고 끝나면
   `emit_poc.py`와 `triage.py`를 한 번 더 돌려 최종 리포트를 만든다.

주요 환경 변수: `TF_BACKEND`, `TF_MODEL`, `CODEX_CMD`, `CODEX_CMD_A` … `CODEX_CMD_E`, `MAX_HOURS`
(기본 12, 양의 정수여야 한다), `SPAWN_ONLY`, `TF_REUSE_SEED`, `TF_CANARY`,
`TF_TOKEN_BUDGET`, `SSRF_HOST`/`SSRF_PORT`(없으면 `CANARY_HOST`/`CANARY_PORT`, 기본
`127.0.0.1:9111`), `TAINTFORGE_EXTRA_CONTEXT`, `TAINTFORGE_DYNAMIC_CONTEXT`, `CWE_XML`, `TF_PY`.
`TF_MAX_REANALYSIS`는 `start.sh`가 tmux 세션으로 전달만 한다. 지금은 `.codex/agents/convergence_c.toml`
안에만 남아 있고 어느 스크립트도 읽지 않는다.

**왜 역할마다 supervisor인가.** 에이전트 턴은 유한하다. 한 역할이 일찍 리턴해도 나머지 넷은 영향을 받지
않고 셸이 그 역할만 다시 띄운다. durable한 coverage/proof ledger/findings/leads 덕에 새 세션이 처음부터
다시 하지 않고 이어 간다.

### 11.4 `start.sh` — tmux 래퍼

`SPAWN_ONLY=1 audit.sh`를 호출하고 tmux 세션(`TAINTFORGE_SESSION`, 기본 `taintforge`)을 만든다. 기존
세션이 있으면 `_stop`을 찍고 `_pids`의 프로세스를 죽인 뒤 세션을 지우고 새로 시작한다.

창은 둘이다.

- `runtime` — `audit.sh` 러너 자체.
- `forge` — 패널 여섯. A / B / C / D / E 로그 tail과 대시보드. 패널 수가 6이 아니면 start.sh가 에러로
  끝난다.

캠페인 범위의 환경 변수(`MAX_HOURS`, `TF_BACKEND`, `TF_MODEL`, `SSRF_*`, `CODEX_CMD*` 등)는 명시적으로
작은 런처 스크립트(`workspace/_runner.sh`)에 써서 넘긴다. 오래 사는 tmux 서버는 자기를 처음 만든
클라이언트의 환경을 유지하기 때문에, 그러지 않으면 동시에 도는 두 타깃 세션이 서로의 URL 컨텍스트와 모델
override, canary를 물려받는다. 멀티라인 미션 값이 사용자 기본 셸을 거치며 argv 하나로 살아남지 못하는
문제도 이 런처 파일이 해결한다.

`TF_BACKEND=claude`면 로그가 stream-json JSONL이라 패널에서 `.agents/stream_fmt.py`로 사람이 읽을 수
있게 렌더링한다. 패널 제목에는 역할이 실제로 도는 모델 이름이 들어간다.

분리는 `Ctrl-b` 다음 `d`(세션은 계속 돈다). 재접속은 `tmux attach -t taintforge`.
`TAINTFORGE_NO_ATTACH=1`이면 붙지 않고 바로 리턴한다.

### 11.5 `campaigns/` — 타깃별 설정

**캠페인**은 평가 대상 하나다. 어느 체크아웃인지, 어느 라이브 URL인지, 어떤 계정인지, 어떤 모듈이 전체
코드 모델을 받는지, 그 코드베이스에서 역할이 알아야 할 것이 무엇인지. 전부 하네스가 아니라 설정이라
이 디렉터리에서는 `README.md`와 `example.*` 한 쌍만 git에 들어간다. 나머지는 `.gitignore`가 막는다.

캠페인은 파일 둘이다.

| File | What it holds |
|---|---|
| `<name>.modules` | 한 줄에 `name:path` — 각각 `workspace/cm/<name>.json`에 전체 모델을 받을 보안 관련 영역. `#` 주석과 빈 줄은 무시 |
| `<name>.sh` | env(타깃, URL, 계정, 백엔드, 모델, canary) + `TAINTFORGE_EXTRA_CONTEXT`, 그리고 `exec ./start.sh ...` |

```bash
./seed.sh targets/<app> campaigns/<name>.modules   # once per checkout
./campaigns/<name>.sh                              # run the roles
```

모듈 목록은 타깃의 보안 경계를 짊어진 영역을 고른다(라우팅, 인증, admin, API 표면, 파서, 템플릿/렌더,
업로드, 플러그인/익스텐션 로딩). 트리 전체가 아니다.

`TAINTFORGE_EXTRA_CONTEXT`에는 역할이 싸게 유도할 수 없는 타깃별 사실만 넣는다.

- 분석 중인 정확한 태그/커밋, 그리고 파인딩을 거기 고정해야 한다는 것
- 라이브 인스턴스의 모양: 로그인 라우트, nonce/CSRF 메커니즘, 어떤 계정이 있고 각각 무엇을 할 수 있는지
- **이 스택에서 추출기의 정직한 한계** — 예컨대 PHP에서는 호출 그래프가 훅 디스패치(`add_action`/
  `apply_filters`), 가변 함수, `call_user_func`를 놓치므로 그래프 엣지는 읽어서 확인할 힌트지 보고할
  경로가 아니다
- 이 벤더의 disclosure 사다리가 실제로 어디 있는지(이슈 트래커, 릴리스 노트, 어드바이저리 피드).
  GitHub 하나로 끝나는 경우가 드물다
- 라이브 URL이 없는 타깃이면 `export TF_CANARY=1`과 빌드한 사본의 랩 격리 규칙

역할 계약 자체는 `AGENTS.md`와 `.agents/skills/`에 둔다. 방법론을 다시 설명하기 시작한 캠페인은 설정이기를
그만둔 것이다.

### 11.6 `test.sh` — 하네스 자체 테스트

```bash
./test.sh
```

`write_finding.py`, `proof_ledger.py`, `triage.py`의 게이트가 TaintForge를 프롬프트가 아니라 하네스로
만드는 부분이라 증명 가능하게 동작해야 한다. 셋 중 하나라도 건드렸으면 이걸 돌린다. 확인하는 것:

- 전제 조건 — `jsonschema`가 있는지(없으면 `write_finding.py`가 검증을 조용히 건너뛴다), 두 스키마가
  파싱되는지
- 셸 문법 — `audit.sh`, `start.sh`, `seed.sh`, `campaigns/example.sh`
- 게이트 테스트 — `.agents/skills/convergence/tests/test_*.py`
  (`test_evidence_contract.py`, `test_official_review_gate.py`)

---

## 12. 엔드투엔드 워크플로

```
1. SEED        seed.sh: build_code_model.sh + per-module models + coverage --init + gen_hypotheses
2. SPAWN       audit.sh launches five supervised role sessions; canary.py with --url or TF_CANARY=1
3. PRODUCE     A (sink -> source, flow shape) and B (entry -> resource, missing-control shape) stream
                 -> write_finding.py -> workspace/findings/<id>.json  [status: candidate]
                 + deep-dive on parser/deserializer/dispatcher code: leads.py (leads/primitives/notes)
                 + proof_ledger.py --done per route/sink unit (finding | safe+evidence | needs_reanalysis)
4. CONVERGE    C loops:
                 a. cross_validate.sh + correlate.py        -> cross_validated
                 b. probe.py / browser_probe.py / canary.py -> reproduced  (live PoC)
                 c. official/vendor product-boundary review -> confirmed | not_product_vulnerability
                 d. evidence contract (shape, reachability, preconditions, ceiling)
                 e. public-history ladder                   -> known | novel | inconclusive
                 f. agent writes poc.py -> repro.poc_script -> emit_poc.py -> report/<id>/
                 g. triage.py -> report/report.md (ranked, gated 0-day section)
5. WEAPONIZE   D takes confirmed + reportable critical findings -> exploit{} + report/<id>/exploit.py
6. FEEDBACK    inconclusive repro -> needs_reanalysis -> E diagnoses -> back to C or false_positive
7. CONTINUE    a role session that returns is respawned by its own supervisor after 5s
8. STOP        touch workspace/_stop; kill $(cat workspace/_pids)
```

### 예시: IDOR 하나의 끝에서 끝까지

1. **B**가 `OrderController@show → OrderRepo::findById(id)`를 따라가며 경로에 소유권 검사가 없음을 본다.
   track B, `defect_shape: "missing_control"`, CWE-639 후보를 기록하고 `missing_control`에 어떤 검사가
   어디 있어야 하는지, 어떤 경로가 그것 없이 닿는지, 누가 걸을 수 있는지를 적는다. `reachability`에
   엔트리 포인트와 최소 권한을 함께 채운다.
2. **C**가 교차 검증을 건너뛰고(로직 파인딩) 바로 재현한다. alice와 bob으로 각각 로그인해 bob의 리소스
   id를 alice의 세션으로 요청하고 `200`과 bob의 데이터를 받는다 → `reproduced`, `repro.success=true`,
   두 아이덴티티의 요청을 `repro.poc`에.
3. **C**가 공식/벤더 리뷰를 한다. 이게 제품의 문서화된 접근 제어 경계를 깨는지, 아니면 애플리케이션이
   잘못 설정한 것인지. 제품 경계 위반이면 `official_review.verdict=product_vulnerability`와 1차 URL을
   기록하고 증거 계약(`defect_shape`, `reachability`, `preconditions`, `primitive.escalation_ceiling`)을
   채워 `confirmed`로 올린다.
4. **C**가 공개 이력 사다리를 탄다. 영향 경로와 심볼로 `git log -S/-G`, upstream main과 릴리스 브랜치
   비교, 벤더 이슈/PR 검색, 어드바이저리/릴리스 노트. 정확한 일치가 없고 `public_history`가 완전하면
   `disclosure=novel`.
5. **C**가 `requests` 기반 `poc.py`를 쓰고(alice 로그인 → bob 리소스 GET → 유출 단언) `repro.poc_script`에
   저장한다. `emit_poc.py`가 `report/<id>/poc.py`와 `finding.md`를 쓰고 `triage.py`가
   `## ⚠️ Potential 0-day` 아래 올린다.

---

## 13. 실행

### 설치

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install jsonschema pyyaml requests
pip install playwright && python3 -m playwright install chromium   # optional: XSS execution proof
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
export PATH="$HOME/.opengrep/cli/latest:$PATH"
.agents/skills/vuln-track-a/scripts/fetch_rules.sh        # once, online
chmod +x audit.sh start.sh seed.sh test.sh .agents/skills/*/scripts/*.{sh,py}
./test.sh                                                 # harness self-tests
```

`jsonschema`가 없으면 `write_finding.py`가 검증을 조용히 건너뛴다. `test.sh`가 제일 먼저 확인하는 항목이
그것이다.

### 계정 (`accounts.json`)

`{username, password}` 객체의 JSON 배열이다. IDOR/authz 재현에는 **일반 사용자 둘 이상과 admin**이
필요하다.

```json
[
  {"username":"admin","password":"..."},
  {"username":"alice","password":"..."},
  {"username":"bob","password":"..."}
]
```

### 전체 실행 (라이브 타깃)

```bash
./seed.sh targets/<app> campaigns/<app>.modules      # once per checkout
TF_REUSE_SEED=1 ./start.sh -u http://localhost:8080 --accounts accounts.json targets/<app>
```

또는 캠페인 런처로:

```bash
./campaigns/<name>.sh
```

라이브 서비스가 없는 타깃이면 `-u`를 빼고 `TF_CANARY=1`을 준다. `MAX_HOURS=24 ...`로 더 길게 돌린다.
tmux 없이 돌리면 `start.sh`가 그대로 `audit.sh`로 넘어간다.

### 보기 / 멈추기

```bash
# dashboard pane shows it live; headless:
tail -f workspace/_log_C.txt
python3 .agents/skills/convergence/scripts/queue.py --counts
python3 .agents/skills/source-model/scripts/proof_ledger.py --summary
cat workspace/report/report.md
ls workspace/report/*/        # per-vuln poc.py + finding.md (+ exploit.py from D)

# stop EVERYTHING (flag first or the supervisors respawn):
touch workspace/_stop
kill $(cat workspace/_pids) 2>/dev/null
tmux kill-session -t taintforge 2>/dev/null
```

---

## 14. 트러블슈팅

| symptom | cause | fix |
|---|---|---|
| `call_edges: 0` | 구조 빌드 실패 | python3 확인 후 재시드, `workspace/cm/<name>.buildlog`와 역할 로그 확인 |
| 모델에 dataflow / proof ledger가 없음 | 파일 4000개 초과로 자동 graph-only | `seed.sh`에 modules 파일을 줘서 per-module 전체 모델을 만들고 `--model` / `--ledger`로 질의 |
| 호출 그래프가 훅·동적 디스패치를 놓침 | 추출기 한계 | 캠페인의 `TAINTFORGE_EXTRA_CONTEXT`에 한계를 적고 그래프 엣지를 읽어서 확인할 힌트로만 쓴다 |
| probe가 `Operation not permitted` | codex 샌드박스에 네트워크 옵션이 빠짐 | `CODEX_CMD`에 `--sandbox workspace-write --config sandbox_workspace_write.network_access=true` 유지 |
| disclosure가 채워지지 않음 | 라이브 웹 검색 비활성 | `CODEX_CMD`의 `--config web_search=live` 확인 |
| IDOR가 `candidate`에서 멈춤 | 계정이 하나뿐(비교할 피해자 없음) | `accounts.json`에 일반 사용자 2명 이상 |
| 역할 세션이 일찍 끝남 | 에이전트 턴은 유한하다 | 정상이다. supervisor가 5초 뒤 재시작한다. `_log_<role>.txt`의 세션 헤더로 확인 |
| `write_finding.py`가 `confirmed`를 거부 | 재현·공식 리뷰·증거 계약 중 하나가 미충족 | 에러 메시지가 빠진 필드를 그대로 지목한다. 증거가 눈앞에 있을 때 채운다 |
| `novel`이 거부됨 | `public_history`가 불완전 | 사다리 네 범주를 전부 기록하고 head/release 비교를 적는다 |
| `proof_ledger.py --done ... --verdict safe`가 거부됨 | `--evidence`가 없거나 너무 짧음 | 안전하게 만드는 정확한 검사와 그것이 모든 호출자를 덮는 이유를 쓴다 |
| `--verdict finding`이 거부됨 | 그 id의 파인딩 파일이 없음 | `write_finding.py`로 먼저 파인딩을 쓴다 |
| tmux 패널이 6개가 아님 | 패널 생성 실패 | `start.sh`가 `EXPECTED_PANES=6`으로 에러를 낸다. `taintforge:runtime` 창을 본다 |
| `launching...`에서 멈추고 tmux가 안 뜸 | 백그라운드 프로세스가 셸 fd를 붙잡음 | 최신 `audit.sh`/`start.sh`는 fd를 분리한다(`</dev/null >…`) |
| 파인딩은 있는데 리포트가 0건 | `report.md`가 묵음 | 대시보드가 매 사이클 재생성한다. 아니면 `triage.py`를 직접 돌린다 |
| 죽인 세션이 계속 살아남 | `_stop`을 안 만듦 | 죽이기 **전에** `touch workspace/_stop` |
| 실행이 스스로 멈춤 | `TF_TOKEN_BUDGET` 초과로 `budget_guard.py`가 `_stop`을 찍음 | `budget_guard.py --report`로 누적치 확인, 예산 조정 후 `_stop` 삭제 |
| Semgrep이 큰 저장소에서 segfault | Semgrep OSS 코어 | OpenGrep을 쓴다 |
| CodeQL이 PHP를 무시 | CodeQL에 PHP 지원이 없다 | 자동 OpenGrep fallback. `ENGINE=opengrep`으로 강제 가능 |

---

## 15. 설계 원칙

- **에이전트가 찾고 도구가 돕는다.** 모든 파인딩은 역할 세션이 `write_finding.py`로 작성한다.
  SAST/CodeQL은 리드와 교차 확인만 준다.
- **모델과 사냥을 분리한다.** `source-model`이 재사용 가능한 사실을 한 번 만들고 사냥 트랙이 그 위에
  판단을 얹는다.
- **클래스가 아니라 모양으로 라우팅한다.** `flow`와 `missing_control` 두 모양이 트랙 A와 B의 이름이고
  class × shape 매트릭스가 주인 없는 클래스를 남기지 않는다.
- **sink-first이되 양방향으로.** 유한한 싱크 집합에 닻을 내리고 호출 그래프를 거슬러 추론하되, 소스에서
  정방향으로도 민다. 한 방향만 도는 것이 곧 편향이다.
- **필수 패스는 선택이 아니다.** P1~P7 중 하나를 건너뛰면 그 계열 전체를 놓친다. P4/P6/P7은 도구가 없는,
  코드를 읽는 패스다.
- **전수적으로.** 모든 모듈, 모든 싱크/라우트마다 버그를 찾거나 안전한 이유를 증거와 함께 남긴다.
  `safe`는 단위를 영원히 닫는 주장이므로 증거 없이는 기록되지 않는다.
- **재현이 가장 강한 증거다.** 다만 동작의 증거다. 제품 취약점인지는 1차 벤더 자료와의 대조가 정한다.
- **정직한 한계.** 도달성은 엔트리 포인트와 권한이고 전제 조건은 기본값인지 아닌지이고 상승 천장은
  증명된 만큼만이다. 과대 포장은 보고 결함이다.
- **새로움은 증거를 요구한다.** `novel`은 소스 이력, upstream 비교, 벤더 이슈/PR, 어드바이저리까지
  네 범주를 다 돈 기록이 있어야 붙는다.
- **append-only, file-lock 파인딩.** 안정적인 id와 `history` 덕에 다섯 세션이 동시에 써도 안전하고 전부
  감사 가능하다.
