## Clickjacking Protection
- **End-Point**: `/`, `/text/css` 외 1개
- **영향**: 공격자가 웹 사이트를 투명한 프레임 내에 삽입하여 사용자의 클릭을 유도하고, 의도하지 않은 기능 실행이나 민감 정보 유출을 유발할 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Frame-Options`가 설정되어 있지 않아 브라우저가 해당 페이지를 `<frame>`, `<iframe>`, `<object>` 등에서 렌더링하는 것을 제한하지 못함.
- **근거**: `curl "http://host3.dreamhack.games:21995/"` 명령을 통한 확인 시 응답 헤더에 클릭재킹 방지를 위한 설정이 부재함.
- **대응**: 웹 서버 또는 애플리케이션의 모든 응답 헤더에 프레임 렌더링을 제어하는 보안 헤더를 추가해야 함.
- **조치**: HTTP 응답 헤더에 `X-Frame-Options: SAMEORIGIN` 또는 `X-Frame-Options: DENY`를 설정하고, 최신 브라우저 보호를 위해 `Content-Security-Policy: frame-ancestors 'self'`를 적용함.