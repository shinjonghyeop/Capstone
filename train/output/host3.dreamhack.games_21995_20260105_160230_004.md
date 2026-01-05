## MIME Type Confusion
- **End-Point**: `/`, `/text/css` 외 1개
- **영향**: 브라우저가 응답 본문의 내용을 분석하여 MIME 타입을 추측(Sniffing)하는 과정에서 악성 스크립트가 실행되거나 XSS 등 2차 공격에 노출될 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Content-Type-Options: nosniff` 설정이 누락되어 있어 브라우저가 선언된 MIME 타입을 무시하고 임의로 해석할 수 있는 상태임.
- **근거**: `curl "http://host3.dreamhack.games:21995/"` 명령을 통해 응답 헤더를 확인한 결과 해당 보안 헤더가 존재하지 않음을 확인.
- **대응**: 모든 HTTP 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저가 선언된 Content-Type만 따르도록 강제함.
- **조치**: 웹 서버(Nginx, Apache 등) 또는 애플리케이션 프레임워크 설정을 통해 `X-Content-Type-Options: nosniff` 헤더를 일괄 적용함.