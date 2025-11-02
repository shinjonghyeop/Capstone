#!/usr/bin/env python3
"""
Nuclei JSON 결과 필터링 스크립트

Nuclei 스캔 결과에서 필요한 필드만 추출하여 새로운 JSON 파일로 저장합니다.

추출 필드:
- info.description
- info.impact
- info.severity
- info.classification.cve-id
- matched-at
- request
- response
- ip
- curl-command
"""

import json
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any


def extract_vulnerability_info(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    단일 취약점 정보에서 필요한 필드만 추출
    
    Args:
        vuln: 원본 취약점 데이터
        
    Returns:
        필터링된 취약점 데이터
    """
    info = vuln.get('info', {})
    
    # cve-id 추출 (여러 경로에서 시도)
    cve_id = (
        info.get('cve-id') or 
        info.get('classification', {}).get('cve-id') or 
        []
    )
    
    # 필요한 필드만 추출
    filtered = {
        'info': {
            'name': info.get('name', 'N/A'),
            'description': info.get('description', 'N/A'),
            'impact': info.get('impact', 'N/A'),
            'severity': info.get('severity', 'N/A'),
            'classification': {
                'cve-id': cve_id if cve_id else []
            }
        },
        'matched-at': vuln.get('matched-at', 'N/A'),
        'request': vuln.get('request', 'N/A'),
        'response': vuln.get('response', 'N/A'),
        'ip': vuln.get('ip', 'N/A'),
        'curl-command': vuln.get('curl-command', 'N/A')
    }
    
    return filtered


def process_nuclei_json(input_file: str, output_file: str, pretty: bool = True) -> None:
    """
    Nuclei JSON 파일을 처리하여 필터링된 결과 저장
    
    Args:
        input_file: 입력 JSON 파일 경로
        output_file: 출력 JSON 파일 경로
        pretty: 예쁘게 포맷팅할지 여부
    """
    try:
        # 입력 파일 읽기
        print(f"[*] 입력 파일 읽는 중: {input_file}")
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 데이터 구조 확인 및 처리
        filtered_results = []
        total_count = 0
        seen_templates = set()  # template-id 중복 체크용
        duplicates_removed = 0
        
        # Nuclei JSON은 보통 이중 배열 구조 [[{...}]]
        if isinstance(data, list):
            for group in data:
                if isinstance(group, list):
                    for vuln in group:
                        if isinstance(vuln, dict):
                            template_id = vuln.get('template-id', '')
                            
                            # template-id가 이미 처리된 경우 건너뛰기
                            if template_id and template_id in seen_templates:
                                duplicates_removed += 1
                                continue
                            
                            # 새로운 template-id 추가
                            if template_id:
                                seen_templates.add(template_id)
                            
                            filtered_results.append(extract_vulnerability_info(vuln))
                            total_count += 1
                elif isinstance(group, dict):
                    # 단일 딕셔너리인 경우
                    template_id = group.get('template-id', '')
                    
                    if template_id and template_id in seen_templates:
                        duplicates_removed += 1
                        continue
                    
                    if template_id:
                        seen_templates.add(template_id)
                    
                    filtered_results.append(extract_vulnerability_info(group))
                    total_count += 1
        elif isinstance(data, dict):
            # 루트가 딕셔너리인 경우
            filtered_results.append(extract_vulnerability_info(data))
            total_count += 1
        
        print(f"[+] 처리된 취약점 개수: {total_count}")
        if duplicates_removed > 0:
            print(f"[+] 중복 제거된 항목: {duplicates_removed}개")
        
        # 결과 저장
        print(f"[*] 결과 저장 중: {output_file}")
        with open(output_file, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(filtered_results, f, indent=2, ensure_ascii=False)
            else:
                json.dump(filtered_results, f, ensure_ascii=False)
        
        print(f"[✓] 완료! 필터링된 결과가 저장되었습니다: {output_file}")
        
        # 파일 크기 정보
        input_size = Path(input_file).stat().st_size
        output_size = Path(output_file).stat().st_size
        reduction = ((input_size - output_size) / input_size) * 100
        
        print(f"\n[통계]")
        print(f"  원본 파일 크기: {input_size:,} bytes")
        print(f"  필터링 후 크기: {output_size:,} bytes")
        print(f"  감소율: {reduction:.1f}%")
        
    except FileNotFoundError:
        print(f"[!] 오류: 파일을 찾을 수 없습니다: {input_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] 오류: JSON 파싱 실패: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] 예상치 못한 오류: {e}")
        sys.exit(1)


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description="Nuclei JSON 결과에서 필요한 필드만 추출",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예제:
  # 기본 사용
  python filter_nuclei_results.py input.json output.json
  
  # 압축된 형식으로 저장
  python filter_nuclei_results.py input.json output.json --no-pretty
  
  # 같은 이름으로 덮어쓰기
  python filter_nuclei_results.py nuclei.json nuclei_filtered.json

추출되는 필드:
  - info.name: 취약점 이름
  - info.description: 설명
  - info.impact: 영향
  - info.severity: 심각도
  - info.classification.cve-id: CVE 번호
  - matched-at: 발견된 URL
  - request: HTTP 요청
  - response: HTTP 응답
  - ip: 대상 IP
  - curl-command: cURL 명령어
        """
    )
    
    parser.add_argument(
        'input_file',
        help='입력 JSON 파일 경로 (Nuclei 스캔 결과)'
    )
    
    parser.add_argument(
        'output_file',
        nargs='?',
        help='출력 JSON 파일 경로 (기본값: input_filtered.json)'
    )
    
    parser.add_argument(
        '--no-pretty',
        action='store_true',
        help='압축된 형식으로 저장 (기본값: 예쁘게 포맷팅)'
    )
    
    args = parser.parse_args()
    
    # 출력 파일명 자동 생성
    if not args.output_file:
        input_path = Path(args.input_file)
        args.output_file = str(input_path.parent / f"{input_path.stem}_filtered{input_path.suffix}")
    
    # 처리 실행
    process_nuclei_json(
        input_file=args.input_file,
        output_file=args.output_file,
        pretty=not args.no_pretty
    )


if __name__ == "__main__":
    main()