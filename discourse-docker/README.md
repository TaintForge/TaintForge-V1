# Discourse (production) — Docker 빌드/실행

- 외부 포트: **31655 → 컨테이너 80**
- 호스트명: `wsl.evm.pics`

```bash
# 1) discourse_docker 클론
git clone --depth 1 https://github.com/discourse/discourse_docker.git
cd discourse_docker

# 2) app.yml 작성 (samples/standalone.yml에서 expose/env만 아래처럼 수정)
cp samples/standalone.yml containers/app.yml
# expose:
#   - "31655:80"
# env:
#   DISCOURSE_HOSTNAME: "wsl.evm.pics"
#   DISCOURSE_PORT: "31655"
#   DISCOURSE_DEVELOPER_EMAILS: "pocas@theori.io"
#   DISCOURSE_SMTP_ADDRESS: smtp.example.com
#   DISCOURSE_SMTP_USER_NAME: user@example.com
#   DISCOURSE_SMTP_PASSWORD: "pa$$word"
#   DISCOURSE_SKIP_EMAIL_SETUP: "1"

# 3) 빌드 (이미지 = local_discourse/app)
./launcher bootstrap app

# 4) 기동
./launcher start app

# 5) 헬스 체크 (200 + ok)
curl -s http://127.0.0.1:31655/srv/status

# 6) 관리자 계정 생성 (대화형)
./launcher enter app
rake admin:create
exit

# 운영 명령어
./launcher logs app                              # 로그
./launcher enter app                             # 컨테이너 셸
./launcher restart app                           # 단순 재시작
./launcher destroy app && ./launcher start app   # app.yml(env/expose) 변경 반영
./launcher rebuild app                           # 코드/플러그인 변경 반영 (재빌드)

# 클린업
./launcher destroy app
docker rmi local_discourse/app
```

> 비표준 포트일 때 `DISCOURSE_HOSTNAME`에 포트를 붙이지 말고 `DISCOURSE_PORT`를 별도로 지정. 사이트가 만드는 절대 URL에 `:31655`가 정확히 포함됨.
