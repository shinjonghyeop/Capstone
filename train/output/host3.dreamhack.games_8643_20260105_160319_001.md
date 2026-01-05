## Content Security Policy Configuration
- **End-Point**: `/`, `//ping`
- **영향**: 콘텐츠 보안 정책(CSP)이 구성되지 않아 XSS(Cross-Site Scripting) 및 코드 주입 공격에 취약하며, 악성 스크립트 실행을 통해 사용자의 민감한 정보가 탈취될 수 있음.
- **설명**: 대상 URL인 `http://host3.dreamhack.games:8643/`에서 CSP 헤더가 설정되지 않았음. CSP는 브라우저가 신뢰할 수 있는 콘텐츠 출처를 정의하여 비인가된 리소스 로드를 차단하는 보안 메커니즘임.
- **근거**: `curl "http://host3.dreamhack.games:8643/"` 실행 시 응답 헤더에서 `Content-Security-Policy` 설정이 확인되지 않음.
- **대응**: 웹 서버 또는 애플리케이션 응답 헤더에 `Content-Security-Policy`를 추가하고, 신뢰할 수 있는 도메인과 리소스만 허용하도록 정책을 구성해야 함.
- **조치**: 보안 강화를 위해 `default-src 'self'`와 같은 엄격한 기본 정책을 적용하고, 서비스 운영에 필요한 최소한의 외부 리소스 경로만 화이트리스트로 관리하도록 설정함.