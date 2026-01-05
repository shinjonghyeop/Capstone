## Content Security Policy Configuration
- **End-Point**: `/ping`, `/text/css` 외 2개
- **영향**: 브라우저가 신뢰할 수 없는 스크립트를 실행하거나 악의적인 사이트로 데이터를 전송하는 XSS(Cross-Site Scripting), 데이터 인젝션 등 클라이언트 측 공격에 노출될 위험이 있습니다.
- **설명**: 해당 엔드포인트의 응답 헤더에 Content Security Policy(CSP)가 설정되어 있지 않습니다. CSP는 웹 페이지에서 로드하고 실행할 수 있는 리소스를 제어하여 보안을 강화하는 필수적인 방어 메커니즘입니다.
- **근거**: `curl "http://host8.dreamhack.games:23482/ping"` 호출 시 응답 헤더에서 `Content-Security-Policy` 설정이 확인되지 않음.
- **대응**: 웹 서버 또는 애플리케이션의 응답 헤더에 적절한 `Content-Security-Policy`를 정의하여 신뢰할 수 있는 출처의 리소스만 허용하도록 설정해야 합니다.
- **조치**: 응답 헤더에 보안 정책에 맞는 CSP를 추가하십시오. 예: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`