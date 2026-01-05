## Clickjacking Protection
- **End-Point**: `/`, `/r` 외 2개
- **영향**: 공격자가 웹 페이지를 투명한 프레임으로 삽입하여 사용자가 인지하지 못한 상태에서 민감한 기능을 실행하거나 클릭을 유도하는 클릭재킹 공격을 수행할 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Frame-Options`가 설정되어 있지 않아 브라우저가 해당 페이지를 `<iframe>`, `<frame>`, `<object>` 등의 태그 내에 렌더링하는 것을 제한하지 않음.
- **근거**: `curl "http://host8.dreamhack.games:10872/"` 명령을 통해 응답 헤더를 확인한 결과 `X-Frame-Options` 또는 관련 보안 정책이 누락됨을 확인.
- **대응**: 모든 HTTP 응답 헤더에 `X-Frame-Options: SAMEORIGIN` 또는 `X-Frame-Options: DENY`를 설정하고, 최신 브라우저를 위해 `Content-Security-Policy: frame-ancestors 'self'`를 추가로 적용함.
- **조치**: 웹 서버(Nginx, Apache 등)의 설정 파일이나 애플리케이션의 미들웨어에서 전역적으로 보안 헤더가 포함되도록 구성함.