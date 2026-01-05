## MIME Type Confusion
- **End-Point**: `/`, `/r` 외 2개
- **영향**: 브라우저가 리소스의 MIME 타입을 잘못 추측하여 실행함으로써 교차 사이트 스크립팅(`XSS`) 등 악의적인 코드가 실행될 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Content-Type-Options: nosniff` 설정이 누락되어 브라우저의 MIME 스니핑 기능이 활성화된 상태임.
- **근거**: `curl "http://host8.dreamhack.games:10872/"` 명령 결과 응답 헤더에서 해당 옵션이 확인되지 않음.
- **대응**: 모든 HTTP 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저가 정의된 `Content-Type`을 강제하도록 설정함.
- **조치**: 웹 서버 환경 설정 또는 애플리케이션 전역 헤더 설정에 `X-Content-Type-Options: nosniff` 구문을 추가함.