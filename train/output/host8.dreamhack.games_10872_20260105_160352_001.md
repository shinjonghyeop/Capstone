## Content Security Policy Configuration
- **End-Point**: `/`, `/r` 외 2개
- **영향**: 사이트 간 스크립팅(XSS), 클릭재킹 및 기타 코드 주입 공격에 취약해질 수 있으며, 브라우저가 악성 리소스를 로드하는 것을 방지할 수 없음.
- **설명**: `http://host8.dreamhack.games:10872/`를 포함한 주요 엔드포인트에 콘텐츠 보안 정책(CSP) 헤더가 설정되어 있지 않아 보안 위협에 노출됨.
- **근거**: `curl "http://host8.dreamhack.games:10872/"` 실행 시 응답 헤더에서 `Content-Security-Policy` 설정을 확인할 수 없음.
- **대응**: 웹 애플리케이션의 신뢰할 수 있는 리소스 출처를 정의하고, 이를 강제하기 위한 `Content-Security-Policy` 헤더를 응답에 포함해야 함.
- **조치**: 웹 서버 설정 또는 애플리케이션 코드에서 `Content-Security-Policy: default-src 'self';`와 같이 엄격한 정책을 기본으로 적용하고, 필요한 경우에만 예외적인 도메인을 허용하도록 설정함.