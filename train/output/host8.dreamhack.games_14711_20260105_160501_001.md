## Content Security Policy Configuration
- **End-Point**: `/`, `/flag` 외 1개
- **영향**: 사이트 간 스크립팅(XSS), 데이터 주입 및 클릭재킹 등 클라이언트 측 공격에 취약할 수 있음.
- **설명**: 웹 애플리케이션의 응답 헤더에 Content-Security-Policy가 설정되어 있지 않아 브라우저가 로드하는 리소스의 신뢰성을 검증하지 못함.
- **근거**: `curl "http://host8.dreamhack.games:14711/"` 실행 시 응답 헤더에서 CSP 설정이 확인되지 않음.
- **대응**: 서비스 운영 환경에 적합한 보안 정책을 수립하고 CSP 헤더를 적용함.
- **조치**: 웹 서버 설정 또는 애플리케이션 코드에서 `Content-Security-Policy` 헤더를 추가하고 허용할 소스 범위를 정의함.