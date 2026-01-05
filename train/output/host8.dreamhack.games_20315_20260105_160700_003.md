## MIME Type Confusion
- **End-Point**: `/`, `/ping`
- **영향**: 브라우저가 응답 본문의 MIME 타입을 잘못 해석하여 악성 스크립트 실행(XSS)이나 보안 정책 우회 공격에 이용될 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Content-Type-Options: nosniff` 설정이 누락되어 있어, 브라우저가 리소스의 실제 내용에 기반해 MIME 타입을 추측(Sniffing)하는 보안 취약점임.
- **근거**: `curl "http://host8.dreamhack.games:20315/"` 명령을 실행하여 응답 헤더 내 `X-Content-Type-Options` 설정이 부재함을 확인.
- **대응**: 모든 HTTP 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저의 MIME 타입 추측 기능을 비활성화해야 함.
- **조치**: 웹 서버(Nginx, Apache 등) 또는 애플리케이션 프레임워크의 보안 설정을 통해 `X-Content-Type-Options` 헤더를 `nosniff`로 일괄 적용함.