# Android APK 분석 모드

Android 모드는 소유하거나 명시적으로 허가받은 APK를 대상으로
`AndroidManifest.xml → 컴포넌트 코드 → cross-component sink → emulator 재현`을 수행한다.
원본 APK는 `targets/`에서 읽기만 하고 모든 파생물은 `workspace/android/`에 저장한다.

## 역할

| 역할 | 담당 |
|---|---|
| M | Manifest, Activity/alias/Service/Receiver/Provider, intent-filter, exported, SDK, 앱·컴포넌트 권한 |
| L | 컴포넌트 유형별 lifecycle, Binder/AIDL, PendingIntent, activity result, Provider 동작 |
| K | deep link/Intent/Bundle/ClipData/URI grant가 컴포넌트를 넘어 실제 sink로 가는 체인 |
| W | WebView URL 검증, redirect, cookie/header, JS bridge, file/content, Intent URL |
| N | `.so`/JNI/DEX/dynamic loader와 push·SMS/MMS·media 등 자동 처리 경로의 zero-click 후보 |
| C | 독립 정적 검증, emulator 재현, 정확한 adb 기반 PoC, 중복 제거와 triage |

## 실행

정적 모델만 생성:

```bash
./android-audit.sh --seed-only targets/app.apk
```

전체 정적 분석:

```bash
./android-audit.sh targets/app.apk
```

허가된 에뮬레이터 재현 포함:

```bash
./android-audit.sh --serial emulator-5554 targets/app.apk
```

주요 결과는 `workspace/android/ANDROID_MODEL.json`,
`workspace/android/probes.json`, `workspace/findings/`, `workspace/report/`에 생성된다.
백그라운드 실행을 중지할 때는
`touch workspace/_android_stop; kill $(cat workspace/android/_pids)`를 사용한다.

## 도구 계층

- 필수 정적 기반: Java, APK ZIP 검증. 완전한 분석에는 `apktool` 또는 `jadx`가 필요하다.
- 권장 Android SDK: `aapt2`/`apkanalyzer`, `apksigner`, `adb`, Android Emulator.
- 권장 구조 분석: Androguard. AAB/split APK는 bundletool을 추가한다.
- 권장 동적 분석: Frida Python API. objection과 drozer는 수동·IPC 교차검증 보조다.
- 네이티브 심화: `readelf`, `nm`, `objdump`, `strings`, Ghidra headless.
- MobSF는 격리된 baseline/cross-validation 도구이며 finding 작성자가 아니다.

도구 버전과 emulator image/API/ABI를 고정하고, 원본 서명 APK와 패치·테스트 서명 APK
결과를 분리한다.

Frida가 준비된 emulator에서는 다음 tracer가 Intent/WebView/DEX/native load 이벤트를
`workspace/android/telemetry/`에 JSONL로 기록한다.

```bash
python3 .agents/skills/android-convergence/scripts/frida_trace.py \
  --serial emulator-5554 --package com.example --seconds 60
```

## zero-click 판정

다음 전체 경로가 필요하다.

```text
passive remote delivery
  -> 사용자 동작 없음
  -> 자동 parser 선택
  -> attacker bytes가 native/unsafe parser에 도달
  -> 구체적 memory-safety 또는 code-loading 결함
  -> 검증된 execution boundary
```

파서 문자열, `strcpy` import, crash 하나는 lead일 뿐 finding이나 zero-click 증명이 아니다.
결과에는 delivery, interaction, execution boundary, sink, evidence grade와
`candidate/probable/confirmed`를 따로 기록한다.

공개 사례가 보여주는 경계:

- Samsung Qmage CVE-2020-8899는 실제 MMS 자동 디코드 zero-click RCE였지만 최초 경계는
  Samsung Messages 프로세스였고 즉시 kernel/root는 아니었다.
  [Project Zero Part 1](https://projectzero.google/2020/07/mms-exploit-part-1-introduction-to-qmage.html),
  [Part 5](https://projectzero.google/2020/08/mms-exploit-part-5-defeating-aslr-getting-rce.html)
- TikTok CVE-2022-28799는 딥링크→WebView/bridge의 one-click 계정 탈취이지 native RCE나
  zero-click이 아니다.
  [Microsoft 연구](https://www.microsoft.com/en-us/security/blog/2022/08/31/vulnerability-in-tiktok-android-app-could-lead-to-one-click-account-hijacking/)
- Oversecured의 TikTok persistent code execution은 arbitrary write와 dynamic `.so` load의
  중요한 체인이지만 선행 악성 로컬 앱 설치·실행이 필요했다.
  [Oversecured 연구](https://oversecured.com/blog/oversecured-detects-dangerous-vulnerabilities-in-the-tiktok-android-app)
- Samsung Galaxy Store 딥링크 이슈는 privileged APK-install JS API 도달로 기술됐지만
  피해자의 페이지 방문이 필요했다. “RCE” 라벨과 실제 실행 경계를 분리해야 한다.
  [Samsung 2023-01 bulletin](https://security.samsungmobile.com/serviceWeb.smsb?month=01&year=2023)

Android의 intent-redirection 방어와 딥링크 해석은 API/target SDK에 따라 바뀐다.
특히 Android 12의 exported/App Link 변화와 Android 16의 intent-redirection hardening을
API matrix에서 구분한다.
[Android Intent redirection](https://developer.android.com/privacy-and-security/risks/intent-redirection),
[unsafe deep links](https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks)

## 안전 경계

- 하드웨어 기기는 차단하고 `ro.kernel.qemu=1`인 `emulator-*`만 사용한다.
- 외부망 대신 로컬 canary/mock backend, 가짜 계정과 sentinel data만 사용한다.
- service/provider probe는 검토 후 명시적 확인 플래그가 있어야 실행된다.
- credential/token 탈취, persistence, shell payload는 사용하지 않는다.
- OEM/system-app 취약점은 AOSP emulator 결과만으로 확정하지 않는다.
