# campaigns/

**캠페인**은 감사 대상 하나를 가리킨다. 어떤 체크아웃인지, 라이브 URL은 무엇인지, 어떤 계정을
쓰는지, 어느 모듈에 풀 코드 모델을 만들지, 그리고 그 코드베이스를 두고 역할들이 알아야 할
사실이 무엇인지. 전부 설정이지 하네스가 아니다. 그래서 git에 올라가는 건 이 README와
`example.*` 한 쌍뿐이고, 네가 만든 캠페인은 로컬에 남는다(`.gitignore`가 `campaigns/*`를 막는다).

캠페인은 파일 두 개다.

| 파일 | 내용 |
|---|---|
| `<name>.modules` | 한 줄에 `name:path` 하나. 여기 적힌 영역마다 `workspace/cm/<name>.json`에 풀 모델이 생긴다. `#` 주석과 빈 줄은 무시. |
| `<name>.sh` | env(타깃, URL, 계정, 백엔드, 모델, 캐너리) + `TAINTFORGE_EXTRA_CONTEXT`, 마지막에 `exec ./start.sh ...`. |

```bash
./seed.sh targets/<app> campaigns/<name>.modules   # 체크아웃당 한 번
./campaigns/<name>.sh                              # 역할 실행
```

## modules 파일이 필요한 이유

`build_code_model.sh`는 분석 대상 파일이 4000개를 넘으면 **graph-only** 추출로 떨어진다.
graph-only 모델에는 dataflow도, 싱크 집합도, proof ledger도 없다. A와 B가 실제로 질의하는 게
바로 그것들이다. 그래서 `<name>.modules`에 적은 영역마다 자기 모델을 따로 만들고, 역할은 그걸
직접 본다.

```bash
callgraph.py    --model  workspace/cm/<name>.json --sinks
proof_ledger.py --ledger workspace/cm/<name>.proof_ledger.json --next route
```

트리 전체를 넣지 말고 타깃의 보안 경계를 지고 있는 영역을 골라라 — 라우팅, 인증, 관리자,
API 표면, 파서, 템플릿/렌더, 업로드, 플러그인·확장 로딩. 이번 버전에 없는 경로는 건너뛰므로
modules 파일 하나로 업그레이드를 넘길 수 있다.

## `TAINTFORGE_EXTRA_CONTEXT`에 넣을 것

역할이 스스로 알아내기 비싼 타깃별 사실만 넣는다. 그 외는 넣지 마라.

- 분석 중인 정확한 태그/커밋, 그리고 발견은 거기에 고정해야 한다는 점
- 라이브 인스턴스의 생김새: 로그인 경로, nonce/CSRF 메커니즘, 어떤 계정이 있고 각자 뭘 할 수 있는지
- **이 스택에서 추출기가 못 보는 것** — 예를 들어 PHP에서는 훅 디스패치(`add_action`/`apply_filters`),
  가변 함수, `call_user_func`를 콜그래프가 놓친다. 그래서 그래프 엣지는 읽어서 확인할 힌트이지
  보고할 경로가 아니다
- 이 벤더의 디스클로저 사다리가 실제로 어디 있는지(이슈 트래커, 릴리스 노트, 어드바이저리 피드).
  GitHub 하나로 끝나는 경우는 드물다
- URL이 없는 데스크톱/CLI 타깃이면 `export TF_CANARY=1` — `audit.sh`가 out-of-band 캐너리를
  띄우고 직접 정리한다. 여기에 빌드한 사본을 가둘 랩 규칙도 같이 적는다

역할 계약 자체는 `AGENTS.md`와 `.agents/skills/`에 둔다. 캠페인이 방법론을 다시 설명하기
시작했다면 그건 더 이상 설정이 아니다.
