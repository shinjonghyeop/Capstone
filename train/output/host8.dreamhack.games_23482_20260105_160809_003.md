## Clickjacking Protection
- **End-Point**: `/ping`, `/text/css` 외 2개
- **영향**: 공격자가 사용자를 속여 의도하지 않은 버튼 클릭이나 링크 실행을 유도함으로써 설정 변경이나 데이터 유출 등의 비정상적인 행위를 수행하게 할 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Frame-Options`가 설정되어 있지 않아 브라우저가 해당 페이지를 `<iframe>`, `<frame>`, `<object>` 등에서 렌더링하는 것을 제한하지 못함.
- **근거**: ```curl "http://host8.dreamhack.games:23482/ping"``` 명령을 통해 응답 헤더 내 `X-Frame-Options` 설정이 누락되었음을 확인.
- **대응**: 모든 웹 응답 헤더에 프레임 삽입을 제어하는 보안 헤더를 추가하여 신뢰할 수 없는 외부 사이트에서의 페이지 임베딩을 차단해야 함.
- **조치**: 웹 서버 또는 애플리케이션 설정에서 `X-Frame-Options: SAMEORIGIN` 또는 `Content-Security-Policy: frame-ancestors 'self'` 헤더를 적용함.