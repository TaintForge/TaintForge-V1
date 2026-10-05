# TaintForge .NET bounty research plan

Snapshot date: 2026-09-28 (Asia/Seoul)

## 결론

.NET runtime과 ASP.NET Core는 공개 GitHub 저장소에서 개발되는 MIT 라이선스 오픈소스다. 이 캠페인의 기준 타깃은 현재 지원 중인 최신 LTS 패치인 **.NET / ASP.NET Core 10.0.12**로 고정한다. `main`이나 daily build에서만 재현되는 문제는 바운티 범위가 아니므로 신규 결함은 반드시 이 태그에서 재현해야 한다.

현재 로컬 타깃:

| Component | Local path | Tag | Commit | State |
| --- | --- | --- | --- | --- |
| .NET runtime | `targets/dotnet-runtime-10.0.12` | `v10.0.12` | `4271d88e0aebf3d04f188f1334c2220d80555ef6` | clean, detached tag |
| ASP.NET Core | `targets/dotnet-aspnetcore-10.0.12` | `v10.0.12` | `cb21a42eafcd44cc35fad48d99dc82ff7512ce2f` | clean, detached tag |

두 타깃은 `targets/` 정책에 따라 읽기 전용으로 취급한다. 하네스, 코퍼스, 빌드 산출물, 크래시는 타깃 밖에 둔다.

생성한 구조 인덱스:

| Scope | Model | Mode / notable stats |
| --- | --- | --- |
| ASP.NET Core 전체 | `workspace/dotnet-bounty/aspnetcore/CODE_MODEL.json` | graph-only, 10,810 files / 488,667 callsites |
| Kestrel Core | `workspace/dotnet-bounty/aspnetcore-kestrel-core/CODE_MODEL.json` | full, 273 files / 16,795 edges / 296 sink leads |
| CoreCLR VM | `workspace/dotnet-bounty/runtime-coreclr-vm/CODE_MODEL.json` | full, 537 files / 116,537 edges / 303 sink leads |
| CoreCLR JIT | `workspace/dotnet-bounty/runtime-coreclr-jit/CODE_MODEL.json` | full, 282 files / 166,629 edges / 19,299 sink leads |
| 공식 library fuzzing | `workspace/dotnet-bounty/runtime-library-fuzzing/CODE_MODEL.json` | full, 18 files / 797 edges / 6 sink leads |

여기서 `sink leads`는 regex/구조 추출 결과이지 취약점 수가 아니다. 특히 JIT의 수치는 allocator, write, emit 계열 내부 호출이 대량으로 잡힌 결과라 반드시 공격자 입력의 실제 도달성을 역추적해야 한다. 전체 runtime 전역 모델은 생성 파일 때문에 비효율적이어서 중단하고, 공식 권장대로 위 공격면별 full model로 분할했다.

## 공식 범위

- 현재 지원 중인 .NET 및 ASP.NET Core, 다음 버전 RC, 현재 SDK 템플릿, 관련 GitHub Actions가 대상이다.
- Critical 또는 Important 수준의 실제 보안 영향이 필요하다.
- RCE 최고 보상은 고품질 보고서 기준 Critical $40,000 / Important $30,000이다.
- 이미 공개된 취약점, 지원 종료 버전, daily/early beta, .NET 고유 문제가 아닌 IIS/OpenSSL 결함, 일반 애플리케이션의 잘못된 구성은 제외하거나 보상 가능성이 낮다.
- 2026-09-28 현재 지원 버전은 10.0.12 LTS, 9.0.20 STS, 8.0.31 LTS이며 .NET 11 RC1도 일시적으로 지원된다. 기본 연구는 지원 기간이 가장 길고 active support인 10.0.12에 집중한다.

공식 링크:

- [Microsoft .NET Bounty](https://www.microsoft.com/en-us/msrc/bounty-dot-net-core)
- [.NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
- [dotnet/runtime](https://github.com/dotnet/runtime)
- [dotnet/aspnetcore](https://github.com/dotnet/aspnetcore)

## 우선순위 공격면

### P0 — Kestrel pre-auth 프로토콜 파서

가장 먼저 본다. 인증 전에 원격 바이트가 직접 도달하고, 2025년에도 파서 불일치에 의한 Critical request-smuggling 수정이 있었다.

주요 코드:

- HTTP/1 request line, headers, chunked body, `Content-Length`/`Transfer-Encoding` 조합
  - `src/Servers/Kestrel/Core/src/Internal/Http/HttpParser.cs`
  - `src/Servers/Kestrel/Core/src/Internal/Http/Http1ChunkedEncodingMessageBody.cs`
- HTTP/2 frame/state/flow-control와 HPACK
  - `src/Servers/Kestrel/Core/src/Internal/Http2/Http2Connection.cs`
  - `src/Servers/Kestrel/Core/src/Internal/Http2/Http2FrameWriter.cs`
- HTTP/3 frame/state와 QPACK
  - `src/Servers/Kestrel/Core/src/Internal/Http3/Http3FrameReader.cs`
  - `src/Servers/Kestrel/Core/src/Internal/Http3/QPack/`

하네스 방향:

1. 기존 단위 테스트와 microbenchmark를 인프로세스 parser harness로 전환한다.
2. 분할 위치가 다른 `ReadOnlySequence<byte>` 조각을 같은 요청에 적용해 streaming invariant를 검증한다.
3. raw socket Kestrel과 독립 RFC parser/reverse-proxy 앞단의 accept/reject, body length, 다음 요청 경계를 비교한다.
4. HTTP/2·3은 frame 순서, stream lifecycle, integer 경계, dynamic table, cancellation/half-close를 상태 기반으로 생성한다.

Request smuggling 자체는 곧바로 RCE가 아니다. 그러나 pre-auth 경계 우회, 내부 endpoint 도달, 후속 deserialization/upload primitive와 결합될 때만 RCE 체인 후보로 승격한다.

### P0 — runtime parser와 unsafe/native 경계

CoreCLR은 C/C++ 네이티브 코드이고 공식 ASan 적용 과정에서도 buffer overrun, use-after-scope, alloc/free mismatch가 실제로 발견됐다. 2026년의 두 DiaSymReader RCE도 PDB/MSFZ 처리 중 out-of-bounds write였다. 알려진 두 CVE는 제출 대상이 아니지만, **복잡한 포맷 + 길이 계산 + native/managed 경계**가 유효한 패턴임을 보여준다.

우선 탐색:

- `src/coreclr/`: type loader, metadata, ReadyToRun, JIT, GC, interop
- `src/native/` 및 각 library의 native shim: 길이·수명·ownership 변환
- `System.Reflection.Metadata`, PE/assembly metadata, single-file bundle/host parsing
- 압축·archive, encoding/UTF-8, JSON, URI/IP/header parser의 `unsafe`, SIMD, `MemoryMarshal`, `Span<T>` 경계
- 인증서/암호 native wrapper는 외부 라이브러리 자체가 아니라 .NET 고유 marshalling, lifetime, type/length 변환만 본다.

현재 runtime 저장소에는 이미 `src/libraries/Fuzzing/DotnetFuzzing`이 있으며 SharpFuzz + libFuzzer를 사용한다. 기존 대상은 Base64, Base64Url, HTTP headers, IP address, JSON document/writer, NRBF, text encoding, type/assembly name, UTF-8, ZIP archive, SearchValues 등이다. `PooledBoundedMemory`로 버퍼 앞뒤 poison page를 배치하는 패턴도 제공한다. 이 구조를 기준선으로 삼고 **기존 대상의 coverage gap**과 **아직 대상이 아닌 parser**를 우선 추가한다.

### P1 — pooled buffer와 비동기 수명

`ArrayPool<T>`, `MemoryPool<T>`, `PipeReader/PipeWriter`, `ReadOnlySequence<T>`, pooled async state는 고성능 경로에서 널리 공유된다. 다음 invariant를 집중 검사한다.

- 반환된 pooled buffer의 재사용 후 접근
- 중복 return/dispose 또는 소유권 이전 누락
- await/cancel/timeout/connection abort 경합 후 stale memory 노출
- sequence segment 경계에 따라 달라지는 parsing 결과
- Kestrel HTTP/2·3 stream reset과 connection teardown 사이의 lifetime race

관리 코드 예외나 단순 DoS만으로 끝나면 우선순위를 내리고, cross-request data corruption 또는 unsafe/native 접근으로 이어질 때 승격한다.

### P1 — 공개 입력에서 runtime codegen까지의 체인

CoreCLR JIT/NativeAOT/metadata는 RCE 관점에서 중요하지만, 임의 IL/assembly/PDB 입력이 필요한 경우 일반 웹 서버의 pre-auth reachability가 약하다. 따라서 아래 조건을 만족할 때만 높은 우선순위를 준다.

- Kestrel, reflection metadata, plugin/package/template 등 범위 내 기본 기능을 통해 공격자가 입력을 공급할 수 있음
- 잘못된 metadata/type invariant가 JIT, loader, native interop까지 전달됨
- 단순히 공격자가 이미 임의 코드를 로드할 수 있어야 하는 자기 공격이 아님

### P1 — ASP.NET Core 상위 프로토콜

- SignalR JSON/MessagePack framing 및 hub state
- WebSocket upgrade와 HTTP/2 extended CONNECT
- multipart/form parsing, request decompression, static-file range
- authentication handlers, Data Protection, routing/host/path normalization

RCE가 최종 목표지만, request boundary confusion·auth bypass·arbitrary file write/load가 확인되면 체인 primitive로 보존한다.

### P2 — SDK templates와 GitHub Actions

공식 범위에는 현재 SDK 템플릿과 저장소 GitHub Actions도 포함된다. 다만 기본 생성 프로젝트나 공식 workflow에서 직접 재현되는 dependency confusion, command injection, secret exposure처럼 제품 고유의 Critical/Important 영향이 있어야 한다.

## 공개 연구와 과거 취약점에서 얻을 것

아래 항목은 모두 **알려진 사례이므로 그대로 제출하지 않는다**. 신규 하네스·invariant·seed 설계에만 쓴다.

| 사례 | 관찰할 패턴 | 현재 캠페인에서의 용도 |
| --- | --- | --- |
| [CVE-2026-71328](https://github.com/dotnet/runtime/security/advisories/GHSA-63gh-g2x5-x69v), [CVE-2026-69522](https://github.com/dotnet/runtime/security/advisories/GHSA-2j8r-3c22-8565) | PDB/MSFZ 처리 중 heap OOB write | nested length/offset/table parser, native writer의 산술 invariant와 minimization seed 설계 |
| [CVE-2025-21171](https://github.com/dotnet/runtime/security/advisories/GHSA-p54p-p3qm-8vgj) | 특수 요청이 .NET 9 웹 서버 RCE로 분류됨 | 원격 request bytes가 runtime/native 경계까지 가는 경로와 patch-diff 연구 |
| [CVE-2025-55315](https://github.com/dotnet/aspnetcore/security/advisories/GHSA-5rrx-jjjq-q2r5) | HTTP 해석 불일치/request smuggling | parser differential, ambiguous framing, proxy/Kestrel 경계 seed |
| [CoreCLR ASan 도입기](https://devblogs.microsoft.com/cppblog/msvc-address-sanitizer-adoption-in-nets-coreclr/) | buffer overflow, UAF 계열, custom allocator/JIT 때문에 sanitizer 운용이 복잡함 | Checked + ASan build와 crash triage 기준 |
| [.NET runtime security mitigations](https://github.com/dotnet/designs/blob/main/accepted/2021/runtime-security-mitigations.md) | JIT code, W^X, IL 보호, 여러 모듈을 잇는 exploit | crash에서 실제 RCE 가능성을 평가할 때 mitigation과 chain 조건을 명시 |
| [Friday the 13th: JSON attacks](https://blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf) | polymorphic deserialization과 gadget chain | 역사적 방법론만 참고. 앱이 위험한 formatter를 직접 선택한 경우는 보통 제품 결함이 아님 |
| [BinaryFormatter security guide](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide) | untrusted deserialization은 설계상 위험 | “dangerous API 사용”과 runtime 자체의 validation bug를 구분 |
| [Project Zero: Exploiting .NET Managed DCOM](https://projectzero.google/2017/04/exploiting-net-managed-dcom.html) | interop trust boundary와 자동 deserialization chain | .NET Framework/DCOM 중심의 역사 자료. 현재 Core 바운티의 주 타깃으로 보지 않음 |

## 실행 순서

1. **환경 고정:** .NET 10 SDK와 필요한 clang/LLVM 도구를 repo-local 경로에 설치하고 버전을 기록한다. 현재 시스템 기본 SDK는 8.0.415라 10.0.12 소스 기준 빌드에는 부족하다.
2. **공식 fuzz baseline:** `src/libraries/Fuzzing/DotnetFuzzing` 대상들을 로컬에서 smoke/replay하고 corpus·coverage·crash format을 TaintForge workspace로 연결한다.
3. **Kestrel harness:** HTTP/1 parser부터 in-process coverage-guided lane과 loopback socket differential lane을 만든다. 이후 HTTP/2 HPACK/state, HTTP/3 QPACK/state 순서로 확장한다.
4. **runtime native lane:** CoreCLR/NativeAOT를 Checked + ASan으로 최소 subset build하고 metadata/loader/native shim용 libFuzzer harness를 붙인다.
5. **자가수정:** 무의미한 parser reject만 늘면 grammar/semantic repair와 dictionary를 보강하고, coverage 정체 시 새 entry point와 state transition seed를 추가한다.
6. **승격 기준:** stock `v10.0.12`에서 반복 재현되고, sanitizer/명백한 invariant violation이 있으며, 공격자 제어 입력과 Critical/Important 영향이 연결될 때만 finding으로 승격한다.

## 당장 피할 함정

- `main`/nightly에서만 나는 crash를 바운티 후보로 착각하지 않는다.
- 공개 CVE를 재발견한 결과를 신규 후보로 올리지 않는다.
- app-level BinaryFormatter/Newtonsoft 설정 실수를 runtime 취약점으로 부풀리지 않는다.
- 정상적인 `OutOfMemoryException`, parser reject, assertion-only debug failure를 메모리 손상으로 분류하지 않는다.
- IIS/OpenSSL/QUIC 구현 자체의 결함은 .NET 고유 wrapper나 invariant가 없으면 범위 밖이다.
- RCE 주장을 할 때는 “crash → controlled corruption → control-flow/code-load primitive” 각 단계를 따로 증명한다.
