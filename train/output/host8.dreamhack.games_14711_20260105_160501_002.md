## Clickjacking Protection
- **End-Point**: `/`, `/flag` 외 1개
- **영향**: 사용자의 의도와 상관없이 공격자가 조작한 프레임 내에서 버튼 클릭이나 링크 선택을 유도하여 민감한 동작을 수행하게 할 수 있음.
- **설명**: 웹 서버의 응답 헤더에 `X-Frame-Options`가 설정되어 있지 않아, 타 사이트에서 `<iframe>` 등을 통해 해당 페이지를 불러와 렌더링하는 것을 허용하는 상태임.
- **근거**: `curl "http://host8.dreamhack.games:14711/"` 명령을 통한 확인 시 응답 헤더에 `X-Frame-Options` 항목이 존재하지 않음.
- **대응**: 모든 웹 응답에 대해 신뢰할 수 있는 출처에서만 프레임 삽입이 가능하도록 보안 헤더를 구성함.
- **조치**: HTTP 응답 헤더에 `X-Frame-Options: SAMEORIGIN` 또는 `X-Frame-Options: DENY`를 설정하고, 현대적 브라우저를 위해 `Content-Security-Policy: frame-ancestors 'self'` 설정을 권고함.