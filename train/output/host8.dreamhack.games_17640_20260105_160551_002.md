## Clickjacking Protection
- **End-Point**: `//ping`, `/`
- **영향**: 공격자가 웹 페이지를 투명한 프레임으로 삽입하여 사용자가 의도하지 않은 클릭을 유도하고 민감한 기능을 실행하게 할 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Frame-Options`가 설정되어 있지 않아 브라우저가 해당 페이지를 `<iframe>` 등의 프레임 내에 렌더링하는 것을 제한하지 않음.
- **근거**: ```curl "http://host8.dreamhack.games:17640//ping"```
- **대응**: HTTP 응답 헤더에 `X-Frame-Options`를 `DENY` 또는 `SAMEORIGIN`으로 설정하거나 `Content-Security-Policy`의 `frame-ancestors` 지시문을 사용함.
- **조치**: 웹 서버 설정 또는 애플리케이션 코드에서 `X-Frame-Options: SAMEORIGIN` 보안 헤더를 모든 응답에 포함하도록 적용함.