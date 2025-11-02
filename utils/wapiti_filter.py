#!/usr/bin/env python3
import json, sys, argparse
from typing import Any, Dict, List

STRIP_ALWAYS = {"method", "level", "referer", "module", "http_request"}

def sanitize_item(item: Any) -> Any:
    """Remove unwanted keys (except 'wstg'). Keep 'parameter' only if it is not null."""
    if not isinstance(item, dict):
        return item
    pruned = dict(item)
    # remove always (wstg 제외)
    for k in STRIP_ALWAYS:
        pruned.pop(k, None)
    # remove parameter only when null
    if "parameter" in pruned and pruned["parameter"] is None:
        pruned.pop("parameter", None)
    return pruned

def main():
    parser = argparse.ArgumentParser(
        description="Filter Wapiti-style JSON: keep only non-empty vulnerabilities, "
                    "prune fields from each finding (preserve 'wstg'), and drop the top-level 'vulnerabilities' wrapper."
    )
    parser.add_argument("input", help="Input JSON file path")
    parser.add_argument("-o", "--output", help="Output JSON file path (default: stdout)")
    args = parser.parse_args()

    # Read
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate and filter
    vulns: Dict[str, Any] = data.get("vulnerabilities", {})
    if not isinstance(vulns, dict):
        print("[!] 'vulnerabilities' key missing or not an object", file=sys.stderr)
        sys.exit(2)

    # Keep only keys with non-empty list values, and sanitize each item in the list
    result: Dict[str, List[Any]] = {}
    for k, v in vulns.items():
        if isinstance(v, list) and len(v) > 0:
            result[k] = [sanitize_item(it) for it in v]

    # Output WITHOUT the top-level 'vulnerabilities' wrapper
    out = result

    # Write
    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
        else:
            print(json.dumps(out, ensure_ascii=False, indent=2))
    except Exception as e:
        print(f"[!] Failed to write output: {e}", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()