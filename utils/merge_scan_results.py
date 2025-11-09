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
from typing import Dict, List, Set
from collections import defaultdict


def extract_subdomain_from_filename(filename: str) -> str:
    """
    Extract subdomain identifier from nuclei or wapiti filename.

    Examples:
        nuclei_scan_localhost_9991_www_XSS_XSS_level1.php_cve_20251102_185057.json
        -> www_XSS_XSS_level1.php

        wapiti_localhost_9991_www_XSS_XSS_level1_php.json
        -> www_XSS_XSS_level1_php

    Returns:
        Normalized subdomain string
    """
    # Remove file extension
    name = filename.replace('.json', '')

    if name.startswith('nuclei_scan_'):
        # Pattern: nuclei_scan_localhost_9991_{subdomain}_{tag}_{timestamp}
        # Remove prefix
        name = name.replace('nuclei_scan_', '')

        # Remove localhost_9991_ or similar domain prefix
        # Match pattern: localhost_PORT_ or domain_
        name = re.sub(r'^[^_]+_\d+_', '', name)

        # Remove tag suffix (cve, sql, xss) and timestamp
        # Pattern: _{tag}_{timestamp}
        name = re.sub(r'_(cve|sql|xss)_\d{8}_\d{6}$', '', name)

        # Normalize: replace .php with _php for consistency
        name = name.replace('.php', '_php')
        name = name.replace('.html', '_html')

    elif name.startswith('wapiti_'):
        # Pattern: wapiti_localhost_9991_{subdomain}
        # Remove prefix
        name = name.replace('wapiti_', '')

        # Remove localhost_9991_ or similar domain prefix
        name = re.sub(r'^[^_]+_\d+_', '', name)

    return name


def extract_domain_from_filename(filename: str) -> str:
    """
    Extract the main domain (host:port) from nuclei or wapiti filename.

    Examples:
        nuclei_scan_localhost_9991_www_XSS_XSS_level1.php_cve_20251102_185057.json
        -> localhost_9991

        wapiti_localhost_9991_www_XSS_XSS_level1_php.json
        -> localhost_9991
    """
    # Remove file extension
    name = filename.replace('.json', '')

    if name.startswith('nuclei_scan_'):
        # Pattern: nuclei_scan_localhost_9991_...
        name = name.replace('nuclei_scan_', '')
        # Extract domain_port pattern
        match = re.match(r'^([^_]+_\d+)', name)
        if match:
            return match.group(1)
    elif name.startswith('wapiti_'):
        # Pattern: wapiti_localhost_9991_...
        name = name.replace('wapiti_', '')
        # Extract domain_port pattern
        match = re.match(r'^([^_]+_\d+)', name)
        if match:
            return match.group(1)

    return 'unknown_domain'


def extract_tag_from_nuclei_filename(filename: str) -> str:
    """
    Extract the scan tag (cve, sql, xss) from nuclei filename.

    Example:
        nuclei_scan_localhost_9991_www_XSS_XSS_level1.php_cve_20251102_185057.json
        -> cve
    """
    match = re.search(r'_(cve|sql|xss)_\d{8}_\d{6}\.json$', filename)
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


def extract_domain_from_subdomain(subdomain: str) -> str:
    """
    Extract the main domain/category from subdomain.

    Examples:
        www_XSS_XSS_level1_php -> www_XSS
        www_SQL_sql1_php -> www_SQL
        www_CommandExecution_CommandExec-1_php -> www_CommandExecution
        www -> www
    """
    # Split by underscore and take first meaningful parts
    parts = subdomain.split('_')

    # Handle special cases
    if len(parts) >= 2:
        # Return first two parts (e.g., www_XSS, www_SQL)
        return f"{parts[0]}_{parts[1]}"
    else:
        # Single part (e.g., www)
        return parts[0]


def merge_scan_results(input_dir: str, output_dir: str):
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

        # Write to output file
        output_filename = f"{domain}.json"
        output_path = os.path.join(output_dir, output_filename)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(subdomains, f, indent=2, ensure_ascii=False)

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


def merge_filtered_results(input_dir: str = "./filtered", output_dir: str = "./merged_results") -> int:
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
        merged_files = merge_scan_results(input_dir, output_dir)
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
