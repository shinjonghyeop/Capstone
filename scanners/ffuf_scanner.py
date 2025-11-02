import os
import subprocess
import json
import shutil
from typing import Dict, Optional, List


# FFUF Configuration
# UNIFIED_WORDLIST = "./scanners/wordlist.txt"
UNIFIED_WORDLIST = "./scanners/wordlist_test.txt"
RECURSION_DEPTH = 2
THREADS = 100
OUTPUT_DIR="./ffuf_output"


def run_ffuf(url: str, output_dir=OUTPUT_DIR, cookies='test=') -> List[str]:
    """
    Execute FFUF unified scan (directories + files) and return URLs

    Args:
        url: Target URL to scan (e.g., http://localhost)
        output_dir: Directory to save JSON results
        cookie: Cookie string for authentication (default: 'test=')

    Returns:
        List of discovered URLs or empty list if failed
    """

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Unified scan (directories + files + extensions + hidden)
    json_file = os.path.join(output_dir, "ffuf_results.json")

    if os.path.exists(UNIFIED_WORDLIST):
        print(f"[FFUF] Running scan ")
        cmd = build_ffuf_command(url, UNIFIED_WORDLIST, json_file, cookies)
        execute_ffuf(cmd, "unified")

        # Parse JSON to URLs (returns list)
        if os.path.exists(json_file):
            result = parse_json_to_urls(json_file)

            # Cleanup: Remove ffuf_output directory
            if os.path.exists(output_dir):
                try:
                    shutil.rmtree(output_dir)
                except Exception as e:
                    print(f"[FFUF] Warning: Failed to cleanup {output_dir}: {e}")
        else:
            result = []
    else:
        print(f"[FFUF] Wordlist not found: {UNIFIED_WORDLIST}")
        result = []

    print(f"[FFUF] Scan completed: {len(result)} URLs found")
    return result


def build_ffuf_command(url: str, wordlist: str, output_path: str, cookie: str) -> list:
    """
    Build FFUF command for unified scan with recursion

    Args:
        url: Target URL
        wordlist: Path to wordlist file
        output_path: Path to save JSON output

    Returns:
        Command list for subprocess
    """
    command = [
        'ffuf',
        '-w', wordlist,
        '-u', f'{url}/FUZZ',
        '-recursion',
        '-recursion-depth', str(RECURSION_DEPTH),
        '-recursion-strategy', 'greedy',
        '-b', cookie,
        '-t', str(THREADS),
        '-s',   # Silent mode
        '-o', output_path,
        '-of', 'json'
    ]
    return command


def execute_ffuf(command: list, scan_name: str) -> bool:
    """
    Execute FFUF command synchronously

    Args:
        command: FFUF command list
        scan_name: Name of scan for logging

    Returns:
        True if successful, False otherwise
    """
    try:

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode == 0:
            return True
        else:
            print(f"  [-] {scan_name} scan failed with code {result.returncode}")
            if result.stderr:
                print(f"  [-] Error: {result.stderr}")
            return False

    except Exception as e:
        print(f"  [-] {scan_name} scan error: {e}")
        return False


def parse_json_to_urls(json_path: str) -> List[str]:
    """
    Parse FFUF JSON results and extract URLs

    Args:
        json_path: Path to FFUF JSON results file

    Returns:
        List of unique URLs or empty list if failed
    """
    try:
        # Read FFUF JSON
        with open(json_path, 'r') as f:
            data = json.load(f)

        # Extract URLs from results
        urls = []
        if 'results' in data and data['results']:
            for result in data['results']:
                if 'url' in result:
                    urls.append(result['url'])

        # Remove duplicates while preserving order
        unique_urls = []
        seen = set()
        for url in urls:
            if url not in seen:
                unique_urls.append(url)
                seen.add(url)

        return unique_urls

    except FileNotFoundError:
        print(f"[FFUF] File not found: {json_path}")
        return []
    except json.JSONDecodeError as e:
        print(f"[FFUF] Invalid JSON format: {e}")
        return []
    except Exception as e:
        print(f"[FFUF] Error parsing FFUF results: {e}")
        return []

'''
# Test code
if __name__ == "__main__":
    """
    Test the FFUF scanner
    Usage: python ffuf_scanner.py
    """

    # Test configuration
    test_url = "http://192.168.0.102:9992"
    test_output = "./ffuf_output"

    print("=" * 50)
    print("FFUF Scanner Test")
    print("=" * 50)

    result_path = run_ffuf(
        url=test_url,
        output_dir=test_output,
        cookie="testtest="
    )

    print("\n" + "=" * 50)
    print("Results:")
    print("=" * 50)
    if result_path and os.path.exists(result_path):
        print(f"  URLs Output: {result_path}")
        print("\nExtracted URLs:")
        with open(result_path, 'r') as f:
            urls = f.read().strip().split('\n')
            for url in urls:
                print(f"    {url}")
        print(f"\n  Total URLs: {len(urls)}")
    else:
        print("  No results")
'''

