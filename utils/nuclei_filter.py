#!/usr/bin/env python3
"""
Nuclei JSON 결과 필터링 모듈

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
import os
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

        # 출력 디렉토리 생성
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(filtered_results, f, indent=2, ensure_ascii=False)
            else:
                json.dump(filtered_results, f, ensure_ascii=False)

        print(f"[✓] 완료! 필터링된 결과가 저장되었습니다: {output_file}")

    except FileNotFoundError:
        print(f"[!] 오류: 파일을 찾을 수 없습니다: {input_file}")
        raise
    except json.JSONDecodeError as e:
        print(f"[!] 오류: JSON 파싱 실패: {e}")
        raise
    except Exception as e:
        print(f"[!] 예상치 못한 오류: {e}")
        raise


def filter_nuclei_results(input_dir: str = "nuclei_results", output_dir: str = "filtered", pretty: bool = True) -> int:
    """
    nuclei_results 디렉토리의 모든 JSON 파일을 필터링하여 filtered 디렉토리에 저장

    Args:
        input_dir: 입력 디렉토리 경로 (기본값: nuclei_results)
        output_dir: 출력 디렉토리 경로 (기본값: filtered)
        pretty: 예쁘게 포맷팅할지 여부

    Returns:
        처리된 파일 개수
    """
    # 입력 디렉토리 확인
    input_path = Path(input_dir)
    if not input_path.exists():
        print(f"[!] 오류: 입력 디렉토리를 찾을 수 없습니다: {input_dir}")
        return 0

    # 출력 디렉토리 생성
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    # JSON 파일 찾기
    json_files = list(input_path.glob("*.json"))

    if not json_files:
        print(f"[!] 경고: {input_dir} 디렉토리에 JSON 파일이 없습니다.")
        return 0

    print(f"\n[+] {len(json_files)}개의 JSON 파일을 발견했습니다.")
    print(f"[+] 필터링 시작: {input_dir} → {output_dir}\n")

    processed_count = 0
    failed_count = 0

    # 각 파일 처리
    for json_file in json_files:
        try:
            print(f"\n{'='*60}")
            print(f"[{processed_count + 1}/{len(json_files)}] 처리 중: {json_file.name}")
            print(f"{'='*60}")

            # 출력 파일 경로 생성
            output_file = output_path / json_file.name

            # 필터링 실행
            process_nuclei_json(
                input_file=str(json_file),
                output_file=str(output_file),
                pretty=pretty
            )

            processed_count += 1

        except Exception as e:
            print(f"[!] {json_file.name} 처리 중 오류 발생: {e}")
            failed_count += 1
            continue

    # 최종 요약
    print(f"\n{'='*60}")
    print(f"[+] 필터링 완료!")
    print(f"{'='*60}")
    print(f"  처리 성공: {processed_count}개")
    print(f"  처리 실패: {failed_count}개")
    print(f"  출력 경로: {output_dir}/")
    print(f"{'='*60}\n")

    return processed_count


