# loco-protocol-kotlin

Kotlin 기반으로 KakaoTalk의 LOCO 프로토콜과 관련 REST 흐름을 연구하고 사용할 수 있게 만든 프로젝트입니다.

이 프로젝트는 연구용입니다.

## 실행

빌드:

```text
gradlew build
```

대화형 CLI 실행:

```text
gradlew run
```

fat jar 빌드:

```text
gradlew buildFatJar
```

jar 실행:

```text
java -jar build/libs/loco-protocol-kotlin.jar
```

## CLI 사용법

프로그램을 실행하면 `kakao>` 프롬프트가 열립니다.

기본 흐름:

```text
bootstrap
rooms --limit 10
read 182072333716551 --limit 20
send 151730524156105 --message "안녕하세요"
quit
```

자주 쓰는 명령:

- `bootstrap`
- `manual-login --email me@example.com --password secret`
- `passcode-request --email me@example.com --password secret`
- `passcode-register --email me@example.com --password secret --passcode 123456`
- `credentials`
- `refresh`
- `rooms --limit 50`
- `room <chatId>`
- `read <chatId> --limit 30`
- `send <chatId> --message "내용"`
- `profile`
- `friends`
- `chats`
- `messages <chatId> --max-pages 3`
- `api-list --verbose`
- `watch-memory`
- `watch-runtime`
- `watch-checkin`
- `quit`

## 로그인 방식

로컬 세션 자동 추출:

```text
bootstrap
```

직접 로그인:

```text
manual-login --email me@example.com --password my-secret-password
```

기기 인증이 필요한 경우:

```text
passcode-request --email me@example.com --password my-secret-password
passcode-register --email me@example.com --password my-secret-password --passcode 123456
```

## 로컬 REST API

서버 실행:

```text
gradlew run --args="server"
```

또는:

```text
java -jar build/libs/loco-protocol-kotlin.jar server
```

API 기본 주소:

```text
http://127.0.0.1:8080
```

자주 쓰는 REST API:

```text
GET  /health
POST /api/credentials/extract?save=true&refresh=true&verifyRest=true
POST /api/auth/login/xvc
POST /api/loco/chats
POST /api/loco/chat-info
POST /api/loco/messages/read
POST /api/loco/messages/send
```

메시지 조회 예시:

```http
POST /api/loco/messages/read
Content-Type: application/json

{
  "chatId": 182072333716551,
  "limit": 20,
  "fetchAll": false,
  "allowOpenChatUnsafe": false
}
```

메시지 전송 예시:

```http
POST /api/loco/messages/send
Content-Type: application/json

{
  "chatId": 151730524156105,
  "message": "안녕하세요",
  "allowOpenChatUnsafe": false
}
```

## 주의

- 문서화되지 않은 Kakao REST/LOCO 경로를 사용합니다.
- 이 프로젝트는 연구용입니다.
