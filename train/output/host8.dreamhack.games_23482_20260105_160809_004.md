## MIME Type Confusion
- **End-Point**: `/ping`, `/text/css` 외 2개
- **영향**: 브라우저가 응답 본문의 내용을 추측하여 실행하는 MIME 스니핑을 허용하여, 공격자가 의도한 악성 스크립트가 실행되는 등 보안 정책이 우회될 수 있음.
- **설명**: 서버의 HTTP 응답 헤더에 `X-Content-Type-Options: nosniff` 설정이 누락되어 있어 브라우저가 선언된 `Content-Type`과 다르게 데이터를 해석할 수 있는 상태임.
- **근거**: `curl "http://host8.dreamhack.games:23482/ping"` 명령을 통한 재현 확인.
- **대응**: 모든 HTTP 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저가 MIME 스니핑을 수행하지 않도록 강제해야 함.
- **조치**: 웹 서버(Nginx, Apache 등) 설정이나 애플리케이션의 보안 미들웨어를 통해 해당 헤더를 전역적으로 적용함.