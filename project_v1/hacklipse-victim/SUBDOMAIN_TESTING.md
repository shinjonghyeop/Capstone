# 서브도메인 퍼징 테스트 가이드

## 🎯 개요

Hacklipse victim 환경에 nginx reverse proxy를 추가하여 실제 서브도메인 퍼징 결과를 얻을 수 있도록 설정했습니다.

## 🏗️ 설정된 서브도메인들

### ✅ 활성 서브도메인 (200, 3xx 응답)
- `victim.local` - WordPress (메인)
- `admin.victim.local` - phpMyAdmin 관리자 인터페이스
- `api.victim.local` - Node.js API 서버
- `blog.victim.local` - WordPress 블로그
- `cms.victim.local` - Drupal CMS
- `dev.victim.local` - Jenkins 개발 도구
- `staging.victim.local` - Apache HTTP 스테이징
- `test.victim.local` - Tomcat 테스트 서버
- `logs.victim.local` - 로그 뷰어

### ⚠️ 제한된 서브도메인 (4xx, 5xx 응답)
- `backup.victim.local` - 403 Forbidden (접근 제한)
- `internal.victim.local` - 401 Unauthorized (인증 필요)
- `ftp.victim.local` - 404 Not Found (서비스 없음)
- `mail.victim.local` - 503 Service Unavailable (서비스 중단)

## 🚀 실행 방법

### 1. Victim 환경 시작
```bash
cd hacklipse-victim
docker compose up -d
```

### 2. /etc/hosts 설정 (로컬 테스트용)
```bash
sudo nano /etc/hosts

# 다음 라인들 추가:
127.0.0.1 victim.local
127.0.0.1 admin.victim.local
127.0.0.1 api.victim.local
127.0.0.1 blog.victim.local
127.0.0.1 cms.victim.local
127.0.0.1 dev.victim.local
127.0.0.1 staging.victim.local
127.0.0.1 test.victim.local
127.0.0.1 logs.victim.local
127.0.0.1 backup.victim.local
127.0.0.1 internal.victim.local
127.0.0.1 ftp.victim.local
127.0.0.1 mail.victim.local
```

### 3. VHost 퍼징 실행
```bash
# 메인 OSINT 파이프라인으로 실행
sudo python3 pipe.py -i 127.0.0.1 -d victim.local -w ./SecLists

# 또는 직접 ffuf로 테스트
ffuf -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u http://victim.local \
     -H "Host: FUZZ.victim.local" \
     -mc 200,204,301,302,307,401,403,500,503 \
     -fc 404 \
     -t 100
```

## 🔍 예상 결과

VHost 퍼징 실행 시 다음과 같은 서브도메인들이 발견될 것입니다:

```
admin.victim.local        [Status: 200, Size: 1234, Words: 456]
api.victim.local          [Status: 200, Size: 2345, Words: 678]
blog.victim.local         [Status: 200, Size: 3456, Words: 890]
cms.victim.local          [Status: 200, Size: 4567, Words: 123]
dev.victim.local          [Status: 200, Size: 5678, Words: 234]
staging.victim.local      [Status: 200, Size: 6789, Words: 345]
test.victim.local         [Status: 200, Size: 7890, Words: 456]
logs.victim.local         [Status: 200, Size: 8901, Words: 567]
backup.victim.local       [Status: 403, Size: 162, Words: 20]
internal.victim.local     [Status: 401, Size: 163, Words: 21]
mail.victim.local         [Status: 503, Size: 164, Words: 22]
```

## 🧪 테스트 검증

### 수동 확인
```bash
# 각 서브도메인 수동 접근
curl -H "Host: admin.victim.local" http://127.0.0.1
curl -H "Host: api.victim.local" http://127.0.0.1
curl -H "Host: backup.victim.local" http://127.0.0.1  # 403 예상
```

### 로그 확인
```bash
# nginx 액세스 로그 확인
docker compose logs nginx-proxy

# 또는 로그 파일 직접 확인
tail -f logs/access.log
```

## 🎛️ 포트 매핑

- **포트 80**: nginx reverse proxy (메인 진입점)
- **포트 8090**: nginx proxy 대체 포트
- **포트 8080-8089**: 개별 서비스 직접 접근 (기존 유지)

## ⚡ ffuf 최적화 옵션

VHost 퍼징을 위한 최적화된 옵션들:

```bash
ffuf -w wordlist.txt \
     -u http://victim.local \
     -H "Host: FUZZ.victim.local" \
     -mc 200,204,301,302,307,401,403,500,503 \
     -fc 404 \
     -fs 162,163,164,165,166 \
     -t 100 \
     -s \
     -o results.json \
     -of json
```

**옵션 설명**:
- `-mc`: 매치할 상태코드들 (다양한 응답 포함)
- `-fc`: 필터링할 상태코드 (404 제외)
- `-fs`: 필터링할 응답 크기 (기본 오류 페이지)
- `-t 100`: 동시 스레드 수
- `-s`: 조용한 모드
- `-o/-of`: JSON 형식 결과 저장

## 🔧 문제 해결

### nginx가 시작되지 않는 경우
```bash
# nginx 설정 파일 검증
docker run --rm -v $(pwd)/nginx-proxy.conf:/etc/nginx/nginx.conf:ro nginx:alpine nginx -t

# 컨테이너 로그 확인
docker compose logs nginx-proxy
```

### 서브도메인이 발견되지 않는 경우
1. /etc/hosts 설정 확인
2. nginx 컨테이너 상태 확인
3. 포트 80이 다른 서비스에서 사용 중인지 확인
4. ffuf 명령어 옵션 재조정

이제 실제 서브도메인 퍼징 환경이 준비되었습니다! 🎉