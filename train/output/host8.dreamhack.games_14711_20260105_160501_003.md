## MIME Type Confusion
- **End-Point**: `/`, `/flag` 외 1개
- **영향**: 브라우저가 응답 본문의 MIME 타입을 추측하여 실행하는 MIME Sniffing 공격에 노출되어 XSS(Cross-Site Scripting) 등의 보안 취약점이 발생할 수 있음.
- **설명**: 서버 응답 헤더에 `X-Content-Type-Options: nosniff` 설정이 누락되어 있어 브라우저가 선언된 Content-Type과 다른 방식으로 리소스를 해석할 위험이 있음.
- **근거**: `curl "http://host8.dreamhack.games:14711/"` 명령 실행 결과 응답 헤더에서 관련 보안 설정이 확인되지 않음.
- **대응**: 모든 HTTP 응답 헤더에 `X-Content-Type-Options: nosniff`를 포함하도록 보안 정책을 수립함.
- **조치**: 웹 서버(Nginx, Apache 등) 또는 애플리케이션 프레임워크 설정에서 `X-Content-Type-Options: nosniff` 헤더를 추가하여 브라우저의 MIME Sniffing 기능을 비활성화함.