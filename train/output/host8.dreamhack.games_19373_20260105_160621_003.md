## MIME Type Confusion
- **End-Point**: `/intro`, `/`
- **영향**: 브라우저가 응답 본문의 내용을 분석하여 MIME 타입을 추측하는 과정에서 공격자가 의도한 악성 스크립트가 실행되는 등 보안 정책 우회 및 XSS 공격에 노출될 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Content-Type-Options: nosniff` 설정이 누락되어 있어, 브라우저가 정의된 `Content-Type`과 다른 형식을 추측하여 실행할 수 있는 상태임.
- **근거**: ```curl "http://host8.dreamhack.games:19373/intro"``` 명령을 통해 대상 엔드포인트의 응답 헤더를 확인한 결과 `X-Content-Type-Options` 설정이 존재하지 않음을 확인함.
- **대응**: 모든 HTTP 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저가 서버에서 지정한 MIME 타입만을 사용하도록 강제해야 함.
- **조치**: 웹 서버(Nginx, Apache 등) 설정 파일이나 애플리케이션 보안 미들웨어 설정을 통해 `X-Content-Type-Options` 헤더 값을 `nosniff`로 일괄 적용함.