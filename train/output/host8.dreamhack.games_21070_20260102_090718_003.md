## MIME Type Confusion
- **End-Point**: `/`
- **영향**: 브라우저가 응답 본문의 내용을 추측하여 실행하는 MIME 스니핑을 통해 의도하지 않은 스크립트가 실행되거나 크로스 사이트 스크립팅(XSS) 공격에 노출될 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Content-Type-Options`가 설정되어 있지 않아, 브라우저가 리소스의 MIME 타입을 임의로 해석할 수 있는 취약점임.
- **근거**: `curl "http://host8.dreamhack.games:21070/"` 명령을 통해 응답 헤더를 확인한 결과 `X-Content-Type-Options` 헤더가 존재하지 않음.
- **대응**: 서버의 모든 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저가 선언된 Content-Type을 강제로 따르도록 설정함.
- **조치**: 웹 서버 설정(Nginx, Apache 등)이나 애플리케이션 프레임워크의 보안 설정을 통해 전역적으로 `X-Content-Type-Options: nosniff` 헤더를 적용함.