## Content Security Policy Configuration
- **End-Point**: `/`
- **영향**: 웹 브라우저가 신뢰하지 않는 스크립트나 리소스를 실행할 수 있게 되어 XSS(Cross-Site Scripting) 및 클릭재킹 등 다양한 클라이언트 사이드 공격에 노출될 위험이 있음.
- **설명**: 대상 서버의 응답 헤더에 콘텐츠 보안 정책(CSP)이 설정되어 있지 않아 브라우저가 리소스의 출처를 제한하지 못하는 상태임.
- **근거**: ```curl "http://host8.dreamhack.games:14330/"``` 명령을 통한 응답 확인 시 `Content-Security-Policy` 헤더가 존재하지 않음.
- **대응**: 웹 애플리케이션에서 사용하는 리소스의 출처를 정의하고 신뢰할 수 있는 도메인만 허용하는 CSP 정책을 수립함.
- **조치**: 웹 서버 설정 또는 애플리케이션 코드에서 `Content-Security-Policy` 응답 헤더를 추가하고 보안 요구 사항에 맞는 지시문(예: `default-src 'self'`)을 구성함.