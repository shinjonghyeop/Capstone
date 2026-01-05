## Content Security Policy Configuration
- **End-Point**: `//ping`, `/`
- **영향**: Content Security Policy(CSP)가 설정되지 않아 XSS(Cross-Site Scripting), 클릭재킹, 코드 주입 등의 클라이언트 측 공격에 취약할 수 있습니다.
- **설명**: 지정된 URL 응답 헤더에 CSP 설정이 누락되어 브라우저가 신뢰할 수 있는 콘텐츠 소스를 제한하지 못하는 상태입니다.
- **근거**: `curl "http://host8.dreamhack.games:17640//ping"` 실행 시 응답 헤더에서 `Content-Security-Policy` 설정이 확인되지 않습니다.
- **대응**: 웹 서버 또는 애플리케이션 설정에서 `Content-Security-Policy` 헤더를 추가하여 허용된 리소스 출처를 명시해야 합니다.
- **조치**: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`와 같이 보안성이 높은 정책을 적용할 것을 권고합니다.