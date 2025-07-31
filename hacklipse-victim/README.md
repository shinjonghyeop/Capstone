#  Hacklipse Victim Environment

## 개요
OSINT 도구 테스트를 위한 다중 취약 서비스 환경입니다.

##  빠른 시작
```bash
# 환경 시작
./run-all.sh

# 환경 중지
./stop-all.sh
```

## 포함된 서비스들

### 웹 서비스
- **Apache** (8080): PHP, SQL 인젝션, 파일 업로드
- **Nginx** (8081): 디렉터리 리스팅, 백업 파일 노출  
- **WordPress 4.7.1** (8082): CVE-2017-1001000
- **Drupal 7.67** (8083): Drupalgeddon2 (CVE-2018-7600)
- **Node.js Express** (8085): CVE-2022-0155
- **Jenkins 2.121.1** (8086): CVE-2018-1000861
- **Tomcat 8.5.32** (8087): CVE-2017-12615 (File Upload)
- **Apache 2.4.49** (8088): CVE-2021-41773 (Path Traversal)
- **PhpMyAdmin 4.8.1** (8089): CVE-2018-12613 (LFI)
- **Custom Server** (9999): Path Traversal

### 네트워크 서비스
- **MySQL** (3306/3307): 약한 인증, 원격 접속
- **PostgreSQL** (5432): 구 버전 취약점
- **MongoDB 4.4.6** (27017): CVE-2021-32563
- **SSH** (2222): 루트 로그인, 약한 패스워드
- **FTP** (2121): 익명 접속, 쓰기 권한
- **Redis** (6379): 인증 없음
- **SNMP** (1161): 기본 커뮤니티 스트링

##  OSINT 테스트 예시
```bash
# 포트 스캔
nmap -sS -sV localhost

# 웹 기술 식별
whatweb http://localhost:8080

# 취약점 스캔  
nuclei -u http://localhost:8082 -t cves/

# OSINT 수집기 테스트
python3 pipe.py localhost
```

##  예상 탐지 결과
- **nmap**: 15개+ 오픈 포트, 서비스 버전 정보
- **whatweb**: Apache, PHP, WordPress, Drupal, Jenkins, Tomcat 식별  
- **searchsploit**: 다중 CVE 탐지
  - CVE-2022-0155 (Node.js Express)
  - CVE-2018-1000861 (Jenkins)
  - CVE-2017-12615 (Tomcat File Upload)
  - CVE-2021-41773 (Apache Path Traversal)
  - CVE-2018-12613 (PhpMyAdmin LFI)
  - CVE-2021-32563 (MongoDB)
- **nikto**: 웹 서버 취약점 다수 발견

##  보안 주의사항
- **로컬 테스트 환경에서만 사용**
- **테스트 완료 후 즉시 종료**

##  모니터링
- **대시보드**: http://localhost:8084
- **실시간 로그**: docker compose logs -f

##  트러블슈팅
```bash
# 컨테이너 상태 확인
docker compose ps

# 로그 확인
docker compose logs victim-main

# 완전 재시작
./stop-all.sh && ./run-all.sh
```
