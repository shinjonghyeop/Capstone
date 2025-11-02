import json, os, sys
from typing import Any, Dict, List

STRIP_ALWAYS = {"method", "level", "referer", "module", "http_request"}

def _sanitize_item(item: Any) -> Any:
    if not isinstance(item, dict):
        return item
    pruned = dict(item)
    for k in STRIP_ALWAYS:
        pruned.pop(k, None)
    if "parameter" in pruned and pruned["parameter"] is None:
        pruned.pop("parameter", None)
    return pruned

def _filter_one_json(data: Dict[str, Any]) -> Dict[str, List[Any]]:
    vulns: Dict[str, Any] = data.get("vulnerabilities", {})
    result = {}
    for k, v in vulns.items():
        if isinstance(v, list) and len(v) > 0:
            result[k] = [_sanitize_item(it) for it in v]
    return result

def filter_dir(input_dir: str) -> List[str]:
    """
    input_dir: json 파일들이 있는 디렉터리
    output: ./filterd/ 디렉터리에 필터링된 json들 저장 (현재 실행 경로 기준)
    return: 저장된 JSON 파일 fullpath 리스트
    """
    if not os.path.isdir(input_dir):
        raise NotADirectoryError(input_dir)

    # ※ 변경된 부분 (현재 working directory 기준)
    outdir = "./filtered"
    os.makedirs(outdir, exist_ok=True)

    saved = []

    for name in os.listdir(input_dir):
        src = os.path.join(input_dir, name)
        if os.path.isfile(src) and name.lower().endswith(".json"):
            try:
                with open(src, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                print(f"[!] read fail {src}: {e}")
                continue

            result = _filter_one_json(data)
            dst = os.path.join(outdir, name)  # same name in ./filterd

            try:
                with open(dst, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=2)
                saved.append(dst)
            except Exception as e:
                print(f"[!] write fail {dst}: {e}")

    return saved