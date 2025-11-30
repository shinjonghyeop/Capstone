#!/usr/bin/env python3
"""
Wapiti JSON 결과 필터링 모듈

Wapiti 스캔 결과에서 불필요한 필드를 제거하고 취약점만 추출합니다.
"""

import json
import os
from typing import Any, Dict, List

# 항상 제거할 필드
STRIP_FIELDS = {"method", "level", "referer", "module", "http_request"}


def _sanitize_item(item: Any) -> Any:
    """취약점 항목에서 불필요한 필드 제거"""
    if not isinstance(item, dict):
        return item

    pruned = {k: v for k, v in item.items() if k not in STRIP_FIELDS}

    # None인 parameter 필드 제거
    if pruned.get("parameter") is None:
        pruned.pop("parameter", None)

    return pruned


def _filter_vulnerabilities(data: Dict[str, Any]) -> Dict[str, List[Any]]:
    """JSON 데이터에서 취약점만 추출하고 정리"""
    vulns = data.get("vulnerabilities", {})
    return {
        category: [_sanitize_item(item) for item in items]
        for category, items in vulns.items()
        if isinstance(items, list) and items
    }


def filter_dir(input_dir: str, output_dir: str = "./filtered") -> List[str]:
    """
    디렉토리 내 모든 Wapiti JSON 파일을 필터링하여 저장

    Args:
        input_dir: 입력 디렉토리 경로
        output_dir: 출력 디렉토리 경로 (기본값: ./filtered)

    Returns:
        저장된 파일 경로 리스트
    """
    if not os.path.isdir(input_dir):
        raise NotADirectoryError(f"디렉토리를 찾을 수 없습니다: {input_dir}")

    os.makedirs(output_dir, exist_ok=True)
    saved = []

    for name in os.listdir(input_dir):
        if not name.lower().endswith(".json"):
            continue

        src = os.path.join(input_dir, name)
        if not os.path.isfile(src):
            continue

        try:
            with open(src, "r", encoding="utf-8") as f:
                data = json.load(f)

            result = _filter_vulnerabilities(data)
            dst = os.path.join(output_dir, name)

            with open(dst, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)

            saved.append(dst)

        except json.JSONDecodeError as e:
            print(f"[!] JSON 파싱 실패 {src}: {e}")
        except IOError as e:
            print(f"[!] 파일 처리 실패 {src}: {e}")

    return saved