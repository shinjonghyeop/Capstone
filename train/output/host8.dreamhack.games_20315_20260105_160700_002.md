## Clickjacking Protection
- **End-Point**: `/`, `/ping`
- **영향**: 공격자가 웹 사이트를 투명한 프레임으로 감싸 사용자의 클릭을 가로채거나, 의도하지 않은 설정 변경 및 데이터 조작 등의 행위를 강제로 수행하게 할 수 있음.
- **설명**: HTTP 응답 헤더에 `X-Frame-Options` 설정이 누락되어 있어 웹 페이지가 다른 도메인의 `<iframe>`, `<frame>`, `<object>` 태그 내에 삽입될 수 있는 상태임.
- **근거**: `curl "http://host8.dreamhack.games:20315/"` 명령을 통해 응답 헤더를 확인한 결과 `X-Frame-Options` 헤더가 존재하지 않음을 확인.
- **대응**: 보안 정책에 따라 모든 응답에 `X-Frame-Options` 또는 `Content-Security-Policy: frame-ancestors` 헤더를 추가하여 프레임 렌더링 허용 범위를 제한해야 함.
- **조치**: 웹 서버 설정에서 `X-Frame-Options`를 `DENY` 또는 `SAMEORIGIN`으로 설정함. (예: Nginx의 경우 `add_header X-Frame-Options "SAMEORIGIN";` 추가)