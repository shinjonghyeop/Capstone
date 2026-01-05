## Content Security Policy Configuration
- **End-Point**: `/`, `/text/css` 외 1개
- **영향**: CSP가 설정되지 않아 XSS(Cross-Site Scripting), 클릭재킹, 데이터 주입 공격 등 악성 스크립트 실행 및 리소스 탈취 위험이 발생할 수 있습니다.
- **설명**: `http://host3.dreamhack.games:21995/` 엔드포인트에서 `Content-Security-Policy` 응답 헤더가 구성되어 있지 않아 브라우저가 실행 가능한 리소스의 출처를 제한하지 못합니다.
- **근거**: `curl "http://host3.dreamhack.games:21995/"` 실행 결과 응답 헤더에서 CSP 설정이 누락된 것을 확인하였습니다.
- **대응**: 웹 애플리케이션의 신뢰할 수 있는 소스 목록을 정의하고, 인라인 스크립트 및 안전하지 않은 리소스 로드를 제한하는 정책을 수립해야 합니다.
- **조치**: 웹 서버 설정 또는 애플리케이션 코드에서 `Content-Security-Policy` 헤더를 추가하고, 서비스 환경에 맞는 지시문(예: `default-src 'self';`)을 적용하십시오.