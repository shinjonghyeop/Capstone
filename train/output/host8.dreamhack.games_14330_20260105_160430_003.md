## MIME Type Confusion
- **End-Point**: `/`
- **영향**: 브라우저가 응답 본문의 내용을 분석하여 MIME 타입을 추측(Sniffing)함으로써, 공격자가 의도한 악성 스크립트가 실행되거나 보안 정책이 우회될 수 있음.
- **설명**: 서버의 응답 헤더에 `X-Content-Type-Options`가 설정되어 있지 않아 브라우저의 MIME 스니핑 기능이 활성화되어 있는 상태임.
- **근거**: `curl "http://host8.dreamhack.games:14330/"` 명령어를 통한 확인 시 응답 헤더에 해당 옵션이 누락됨.
- **대응**: HTTP 응답 헤더에 `X-Content-Type-Options: nosniff`를 추가하여 브라우저가 서버에서 지정한 Content-Type을 강제로 따르도록 설정해야 함.
- **조치**: 웹 서버 설정 또는 애플리케이션 코드 내에서 모든 응답 헤더에 `X-Content-Type-Options: nosniff`가 포함되도록 적용함.