## Clickjacking Protection
- **End-Point**: `/intro`, `/`
- **영향**: 공격자가 대상 웹 페이지를 투명한 프레임 내에 삽입하여 사용자가 의도하지 않은 클릭을 유도함으로써 민감한 기능을 실행하거나 정보를 변조할 수 있음.
- **설명**: 웹 서버의 응답 헤더에 `X-Frame-Options`가 설정되어 있지 않아 브라우저가 해당 페이지를 `<iframe>`, `<frame>`, `<object>` 등의 태그 내에 렌더링하는 것을 허용하는 상태임.
- **근거**: `curl "http://host8.dreamhack.games:19373/intro"` 명령을 통한 확인 결과, 응답 헤더에 `X-Frame-Options` 또는 `Content-Security-Policy: frame-ancestors` 설정이 존재하지 않음.
- **대응**: 모든 HTTP 응답에 대해 프레임 렌더링 정책을 정의하는 보안 헤더를 강제적으로 적용해야 함.
- **조치**: 웹 서버 설정 또는 애플리케이션 코드에서 HTTP 응답 헤더에 `X-Frame-Options: SAMEORIGIN` 또는 `X-Frame-Options: DENY`를 추가하고, 최신 브라우저 호환성을 위해 `Content-Security-Policy: frame-ancestors 'self'` 설정을 권장함.