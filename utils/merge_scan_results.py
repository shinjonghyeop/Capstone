#!/usr/bin/env python3
"""
Scan Results Merger

This script merges nuclei and wapiti scan results by domain.
All subdomains for a domain are merged into a single JSON file.

Output format:
{
    "subdomain1": {
        "nuclei": {
            "cve": [...],
            "sql": [...],
            "xss": [...]
        },
        "wapiti": {...}
    },
    "subdomain2": {
        "nuclei": {...},
        "wapiti": {...}
    },
    ...
}
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict
from datetime import datetime


def _strip_prefix_and_extension(filename: str) -> tuple[str, str]:
    """파일명에서 prefix와 확장자를 제거하고 scanner 타입 반환"""
    name = filename.replace('.json', '')

    if name.startswith('nuclei_scan_'):
        return name.replace('nuclei_scan_', ''), 'nuclei'
    elif name.startswith('wapiti_'):
        return name.replace('wapiti_', ''), 'wapiti'

    return name, 'unknown'


def extract_subdomain_from_filename(filename: str) -> str:
    """
    파일명에서 subdomain 식별자 추출

    예시:
        nuclei_scan_localhost_9991_www_XSS_level1.php_cve_20251102_185057.json
        -> www_XSS_level1_php
    """
    name, scanner_type = _strip_prefix_and_extension(filename)

    # domain_port 패턴 제거
    name = re.sub(r'^[^_]+_\d+_', '', name)

    if scanner_type == 'nuclei':
        # tag와 timestamp 제거
        name = re.sub(r'_(cve|sqli|xss|rce|lfi|ssti|ssrf|csrf)_\d{8}_\d{6}$', '', name)
        # 확장자 정규화
        name = re.sub(r'\.(php|html)$', lambda m: f'_{m.group(1)}', name)

    return name


def extract_domain_from_filename(filename: str) -> str:
    """
    파일명에서 도메인(host:port) 추출
    IP 주소와 일반 도메인을 모두 지원

    예시:
        nuclei_scan_localhost_9991_www_XSS.json -> localhost_9991
        nuclei_scan_example.com_8080_... -> example.com_8080
        nuclei_scan_10.64.141.227_cve_... -> 10.64.141.227
        wapiti_10_64_141_227_88daf172.json -> 10.64.141.227
    """
    name, scanner_type = _strip_prefix_and_extension(filename)

    # IP 주소 패턴 감지 (IPv4)
    # 패턴: 10_64_141_227 또는 10.64.141.227
    ip_pattern = r'^(\d{1,3}[._]\d{1,3}[._]\d{1,3}[._]\d{1,3})(?:_|$)'
    ip_match = re.match(ip_pattern, name)

    if ip_match:
        # IP 주소를 점 표기법으로 정규화
        ip_part = ip_match.group(1).replace('_', '.')

        # IP 주소 유효성 검증
        octets = ip_part.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return ip_part

    # 기존 도메인 로직 (호스트명인 경우)
    match = re.match(r'^(.+?)_(\d+)_', name + '_')
    if match:
        domain_part = match.group(1)
        port = match.group(2)

        # wapiti 파일명에서는 점이 언더스코어로 변환됨
        if scanner_type == 'wapiti' and '.' not in domain_part:
            # 언더스코어를 점으로 복원
            parts = domain_part.split('_')
            if len(parts) >= 2:
                domain_part = '.'.join(parts)

        return f"{domain_part}_{port}"

    return 'unknown_domain'


def extract_tag_from_nuclei_filename(filename: str) -> str:
    """
    Extract the scan tag (cve, sql, xss) from nuclei filename.

    Example:
        nuclei_scan_localhost_9991_www_XSS_XSS_level1.php_cve_20251102_185057.json
        -> cve
    """
    match = re.search(r'_(cve|sqli|xss|rce|lfi|ssti|ssrf|csrf)_\d{8}_\d{6}\.json$', filename)
    if match:
        return match.group(1)
    return 'unknown'


def load_json_file(file_path: str) -> Dict:
    """Load and parse a JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Error loading {file_path}: {e}")
        return {}


def group_files_by_subdomain(directory: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Group all scan result files by subdomain.

    Returns:
        {
            "subdomain1": {
                "nuclei": ["file1.json", "file2.json"],
                "wapiti": ["file3.json"]
            },
            ...
        }
    """
    grouped = defaultdict(lambda: {"nuclei": [], "wapiti": []})

    for file_path in Path(directory).glob('*.json'):
        filename = file_path.name

        if filename.startswith('nuclei_scan_'):
            subdomain = extract_subdomain_from_filename(filename)
            grouped[subdomain]["nuclei"].append(str(file_path))
        elif filename.startswith('wapiti_'):
            subdomain = extract_subdomain_from_filename(filename)
            grouped[subdomain]["wapiti"].append(str(file_path))

    return dict(grouped)


def merge_nuclei_results(nuclei_files: List[str]) -> Dict:
    """
    Merge multiple nuclei scan results (cve, sql, xss) into one structure.

    Returns:
        {
            "cve": { ... },
            "sql": { ... },
            "xss": { ... }
        }
    """
    merged = {}

    for file_path in nuclei_files:
        filename = os.path.basename(file_path)
        tag = extract_tag_from_nuclei_filename(filename)
        data = load_json_file(file_path)
        merged[tag] = data

    return merged


def merge_wapiti_results(wapiti_files: List[str]) -> Dict:
    """
    Merge wapiti scan results. Usually there's only one file per subdomain.

    Returns:
        The wapiti scan result JSON
    """
    if not wapiti_files:
        return {}

    # Usually only one wapiti file per subdomain
    if len(wapiti_files) > 1:
        print(f"Warning: Multiple wapiti files for same subdomain: {wapiti_files}")

    return load_json_file(wapiti_files[0])


def create_subdomain_data(files: Dict[str, List[str]]) -> Dict:
    """
    Create merged data structure for a subdomain.

    Returns:
        {
            "nuclei": { ... },
            "wapiti": { ... }
        }
    """
    return {
        "nuclei": merge_nuclei_results(files["nuclei"]),
        "wapiti": merge_wapiti_results(files["wapiti"])
    }


def normalize_endpoint(url: str) -> str:
    """URL에서 쿼리 파라미터와 프래그먼트를 제거하여 base endpoint만 추출"""
    if not url:
        return url
    return url.split('?')[0].split('#')[0]


def convert_to_frontend_format(domain: str, subdomains: Dict) -> Dict:
    """
    Convert merged data to frontend-compatible format.

    Returns:
        {
            "target": "domain:port",
            "startedAt": "...",
            "finishedAt": "...",
            "tools": ["nuclei", "wapiti"],
            "findings": [...]
        }
    """
    findings = []
    tools_used = set()

    for subdomain_key, subdomain_data in subdomains.items():
        # Process nuclei results
        nuclei_data = subdomain_data.get("nuclei", {})
        for tag, results in nuclei_data.items():
            if not results:
                continue

            # results can be a list or dict
            items = results if isinstance(results, list) else [results]

            for item in items:
                if not item:
                    continue

                info = item.get("info", {})

                # Extract CVE if available
                cve_ids = info.get("classification", {}).get("cve-id", [])
                cve_str = None
                if cve_ids:
                    cve_str = ', '.join(cve_ids) if isinstance(cve_ids, list) else cve_ids

                matched_url = item.get("matched-at", "")

                finding = {
                    "id": f"nuclei-{tag}-{len(findings)}",
                    "tool": "nuclei",
                    "category": tag.upper(),
                    "severity": (info.get("severity") or "info").lower(),
                    "title": info.get("name") or f"Nuclei finding ({tag})",
                    "description": info.get("description", ""),
                    "impact": info.get("impact", "N/A"),
                    "endpoint": normalize_endpoint(matched_url),
                    "fullUrl": matched_url,
                    "method": item.get("method", "GET"),
                    "cve": cve_str,
                    "evidence": item.get("matcher-name", ""),
                    "recommendation": info.get("remediation", ""),
                    "references": info.get("reference", []) if isinstance(info.get("reference"), list) else [info.get("reference")] if info.get("reference") else [],
                    "request": item.get("request", ""),
                    "response": item.get("response", ""),
                    "curlCommand": item.get("curl-command", ""),
                    "ip": item.get("ip", ""),
                }

                findings.append(finding)
                tools_used.add("nuclei")

        # Process wapiti results
        wapiti_data = subdomain_data.get("wapiti", {})
        # filtered wapiti 파일은 vulnerabilities 키 없이 바로 카테고리가 최상위
        # 원본 wapiti는 {"vulnerabilities": {...}} 구조
        vulnerabilities = wapiti_data.get("vulnerabilities", wapiti_data)

        for vuln_type, vuln_list in vulnerabilities.items():
            if not vuln_list:
                continue

            for vuln in vuln_list:
                wstg = vuln.get("wstg", [])
                path = vuln.get("path", "")

                # Wapiti level을 severity로 변환 (level은 숫자: 1=low, 2=medium, 3=high)
                level = vuln.get("level", 1)
                severity_map = {1: "low", 2: "medium", 3: "high"}
                severity = severity_map.get(level, "info") if isinstance(level, int) else str(level).lower() if level else "info"

                finding = {
                    "id": f"wapiti-{vuln_type}-{len(findings)}",
                    "tool": "wapiti",
                    "category": vuln_type,
                    "severity": severity,
                    "title": vuln_type,
                    "description": vuln.get("info", ""),
                    "endpoint": normalize_endpoint(path),
                    "fullUrl": path,
                    "method": vuln.get("method", ""),
                    "parameter": vuln.get("parameter", ""),
                    "evidence": vuln.get("parameter", ""),
                    "recommendation": vuln.get("solution", ""),
                    "wstg": wstg,
                    "references": [f"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/{tag}" for tag in wstg] if wstg else [],
                    "curlCommand": vuln.get("curl_command", ""),
                }

                findings.append(finding)
                tools_used.add("wapiti")

    # Convert domain format (e.g., "example.com_8080" -> "example.com:8080")
    target = domain.replace("_", ":", 1) if "_" in domain else domain

    return {
        "target": target,
        "startedAt": datetime.now().isoformat(),
        "finishedAt": datetime.now().isoformat(),
        "tools": list(tools_used),
        "findings": findings
    }


def merge_scan_results(input_dir: str, output_dir: str, run_timestamp: Optional[str] = None):
    """
    Main function to merge all scan results by domain.
    All subdomains for each domain are merged into a single JSON file.

    Args:
        input_dir: Directory containing filtered scan results
        output_dir: Directory to write merged JSON files
    """
    print("=" * 80)
    print("Scan Results Merger (Domain-Level)")
    print("=" * 80)
    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    print()

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Group files by subdomain first
    print("Step 1: Grouping files by subdomain...")
    subdomain_groups = group_files_by_subdomain(input_dir)
    print(f"Found {len(subdomain_groups)} unique subdomains")
    print()

    # Group subdomains by domain
    print("Step 2: Grouping subdomains by domain...")
    domain_data = defaultdict(dict)

    for subdomain, files in subdomain_groups.items():
        # Extract domain from the first file
        if files["nuclei"]:
            first_file = os.path.basename(files["nuclei"][0])
        elif files["wapiti"]:
            first_file = os.path.basename(files["wapiti"][0])
        else:
            continue

        domain = extract_domain_from_filename(first_file)

        # Create subdomain data
        subdomain_data = create_subdomain_data(files)

        # Add to domain data with subdomain as key
        domain_data[domain][subdomain] = subdomain_data

    print(f"Found {len(domain_data)} unique domains")
    print()

    if not run_timestamp:
        run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Write one JSON file per domain
    print("Step 3: Creating merged JSON files...")
    merged_files = []

    for domain, subdomains in sorted(domain_data.items()):
        print(f"Processing domain: {domain}")
        print(f"  Subdomains: {len(subdomains)}")

        # Count total files
        total_nuclei = sum(
            1 for sd_data in subdomains.values()
            for tag_data in sd_data["nuclei"].values()
            if tag_data
        )
        total_wapiti = sum(1 for sd_data in subdomains.values() if sd_data["wapiti"])

        print(f"  Total nuclei scans: {total_nuclei}")
        print(f"  Total wapiti scans: {total_wapiti}")

        # Convert to frontend format and write to output file
        frontend_data = convert_to_frontend_format(domain, subdomains)

        output_filename = f"{domain}_{run_timestamp}.json"
        output_path = os.path.join(output_dir, output_filename)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(frontend_data, f, indent=2, ensure_ascii=False)

        print(f"  Total findings: {len(frontend_data['findings'])}")

        merged_files.append(output_path)
        print(f"  ✓ Created: {output_filename}")
        print()

    # Summary
    print("=" * 80)
    print("Summary:")
    print(f"  Total domains processed: {len(domain_data)}")
    print(f"  Total subdomains: {len(subdomain_groups)}")
    print(f"  Domain-level JSON files created: {len(merged_files)}")
    print(f"  Output directory: {output_dir}")
    print()
    print("✓ Domain-level merge completed successfully!")
    print("=" * 80)

    return merged_files


def merge_filtered_results(
    input_dir: str = "./filtered",
    output_dir: str = "./merged_results",
    run_timestamp: Optional[str] = None
) -> int:
    """
    Wrapper function for easy import and use as a module.

    Args:
        input_dir: Directory containing filtered scan results (default: "./filtered")
        output_dir: Directory to write merged JSON files (default: "./merged_results")

    Returns:
        Number of domain-level JSON files created, or 0 if error
    """
    try:
        # Check if input directory exists
        if not os.path.exists(input_dir):
            print(f"[!] Error: Input directory '{input_dir}' does not exist")
            return 0

        # Run merge
        merged_files = merge_scan_results(input_dir, output_dir, run_timestamp=run_timestamp)
        return len(merged_files)

    except Exception as e:
        print(f"[!] Error during merge: {e}")
        return 0


if __name__ == "__main__":
    import sys

    # Default paths
    input_dir = "./filtered"
    output_dir = "./merged_results"

    # Check if input directory exists
    if not os.path.exists(input_dir):
        print(f"Error: Input directory '{input_dir}' does not exist")
        sys.exit(1)

    # Run merge
    result = merge_filtered_results(input_dir, output_dir)

    if result > 0:
        print(f"\n[SUCCESS] {result} domain-level JSON file(s) created")
        sys.exit(0)
    else:
        print("\n[ERROR] Merge failed")
        sys.exit(1)
