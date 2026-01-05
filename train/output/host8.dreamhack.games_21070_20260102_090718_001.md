## Content Security Policy Configuration
- **End-Point**: `/`
- **영향**: CSP 헤더가 부재할 경우 사이트 간 스크립팅(XSS), 클릭재킹 및 기타 코드 인젝션 공격에 대한 방어 계층이 누락되어 공격자가 사용자의 브라우저에서 악성 스크립트를 실행하거나 민감한 정보를 탈취할 위험이 있음.
- **설명**: 대상 URL(`http://host8.dreamhack.games:21070/`)에 콘텐츠 보안 정책(CSP)이 설정되어 있지 않음. CSP는 브라우저가 로드할 수 있는 리소스의 출처를 제한하여 보안을 강화하는 중요한 보안 메커니즘임.
- **근거**: `curl "http://host8.dreamhack.games:21070/"` 명령을 통한 확인 결과, 서버의 응답 헤더에 `Content-Security-Policy` 항목이 포함되어 있지 않음.
- **대응**: 웹 애플리케이션의 보안 강화를 위해 신뢰할 수 있는 리소스 출처를 정의하는 Content-Security-Policy 응답 헤더를 구성하고 적용해야 함.
- **조치**: 서버 설정 또는 애플리케이션 코드에서 `Content-Security-Policy` 헤더를 추가함. 예시: `Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com;`와 같이 서비스 운영에 필요한 최소한의 권한으로 정책을 수립하여 적용함.