## MIME Type Confusion
- **End-Point**: `//ping`, `/`
- **영향**: 브라우저가 응답 본문의 내용을 분석하여 MIME 타입을 임의로 결정하는 MIME 스니핑이 발생할 수 있으며, 이를 통해 공격자가 의도한 악성 스크립트가 실행되어 XSS(Cross-Site Scripting) 등의 보안 위협이 발생할 수 있음.
- **설명**: 서버 응답 헤더에 `X-Content-Type-Options` 설정이 누락되어 있어, 브라우저가 리소스의 MIME 타입을 추측하여 실행할 수 있는 상태임.
- **근거**: `curl "http://host8.dreamhack.games:17640//ping"` 명령 실행 시 응답 헤더에서 `X-Content-Type-Options: nosniff` 항목이 확인되지 않음.
- **대응**: 웹 서버 또는 애플리케이션의 모든 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저의 임의적인 MIME 타입 해석을 방지해야 함.
- **조치**: 서버 설정 파일이나 애플리케이션 보안 미들웨어에서 `X-Content-Type-Options` 헤더를 `nosniff`로 일괄 적용함.