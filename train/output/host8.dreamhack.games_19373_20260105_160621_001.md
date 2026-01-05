## Content Security Policy Configuration
- **End-Point**: `/intro`, `/`
- **영향**: 사이트 간 스크립팅(XSS), 데이터 주입, 클릭재킹 등 클라이언트 측 보안 취약점을 이용한 공격에 노출될 수 있습니다.
- **설명**: 지정된 엔드포인트에서 콘텐츠 보안 정책(CSP) 헤더가 설정되어 있지 않아 브라우저가 신뢰할 수 있는 리소스만 로드하도록 제한하지 못하는 상태입니다.
- **근거**: `curl "http://host8.dreamhack.games:19373/intro"` 명령 실행 시 응답 헤더에 CSP 관련 설정이 존재하지 않음을 확인하였습니다.
- **대응**: 웹 서버 설정 또는 애플리케이션 응답 헤더에 적절한 Content-Security-Policy를 정의하여 허용된 출처의 리소스만 실행되도록 제한해야 합니다.
- **조치**: 웹 서버 설정 파일이나 프레임워크 보안 설정을 통해 `Content-Security-Policy: default-src 'self';`와 같은 보안 헤더를 추가합니다.