"""Katana integration for web crawling and JavaScript discovery."""
import subprocess
import tempfile
import os
import shutil
from typing import List, Tuple, Optional
from pathlib import Path
import requests
from urllib.parse import urlparse


def check_katana_installed() -> Tuple[bool, Optional[str]]:
    """Check if Katana is installed and available.

    Returns:
        Tuple of (is_installed, version_or_error)
    """
    try:
        result = subprocess.run(
            ['katana', '-version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Extract version from output
            version = result.stdout.strip() or result.stderr.strip()
            return True, version
        return False, "Katana command failed"
    except FileNotFoundError:
        return False, "Katana not found. Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest"
    except subprocess.TimeoutExpired:
        return False, "Katana version check timed out"
    except Exception as e:
        return False, f"Error checking Katana: {str(e)}"


def crawl_with_katana(url: str, timeout: int = 120, verbose: bool = False) -> Tuple[bool, List[str], Optional[str]]:
    """Crawl a website using Katana to discover JavaScript files.

    Args:
        url: Target URL to crawl
        timeout: Timeout in seconds
        verbose: Show verbose output

    Returns:
        Tuple of (success, list_of_urls, error_message)
    """
    # Check if Katana is installed
    is_installed, version_or_error = check_katana_installed()
    if not is_installed:
        return False, [], version_or_error

    # Parse URL to get domain for filtering
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path

    # Build filter pattern to include target domain and supabase
    # This will capture both the target site and any supabase API calls
    filter_pattern = f"(.*{domain}.*|.*supabase.*)"

    # Build Katana command
    # -u: URL target
    # -jsl: JavaScript link extraction
    # -jc: JavaScript crawling
    # -silent: Silent mode (only URLs in output)
    # -fs: Field scope filter
    # -nc: No color in output
    katana_cmd = [
        'katana',
        '--silent',
        '-u', url,
        '-jsl',  # JavaScript link extraction
        '-jc',   # JavaScript crawling
        '-nc',   # No color
        '-fs', filter_pattern
    ]

    if verbose:
        print(f"[Katana] Running command: {' '.join(katana_cmd)}")

    try:
        result = subprocess.run(
            katana_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            return False, [], f"Katana failed: {error_msg}"

        # Parse output - each line is a URL
        urls = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]

        if verbose:
            print(f"[Katana] Discovered {len(urls)} URLs")

        return True, urls, None

    except subprocess.TimeoutExpired:
        return False, [], f"Katana timed out after {timeout} seconds"
    except Exception as e:
        return False, [], f"Error running Katana: {str(e)}"


def filter_javascript_urls(urls: List[str]) -> List[str]:
    """Filter URLs to keep only JavaScript files.

    Args:
        urls: List of URLs from Katana

    Returns:
        List of JavaScript file URLs
    """
    js_urls = []
    seen_urls = set()
    js_extensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs']

    # Invalid patterns to skip
    invalid_patterns = [
        '/assets/Node.js',  # Common false positive
        '/.well-known/',    # JWKS and other configs (not JS)
        '/assets/assets/',  # Duplicate paths
        '/node_modules/',   # Node modules references
    ]

    for url in urls:
        # Skip if already seen (deduplicate)
        if url in seen_urls:
            continue

        # Skip invalid patterns
        if any(pattern in url for pattern in invalid_patterns):
            continue

        # Check if URL ends with JavaScript extension
        path_without_query = url.split('?')[0]

        if any(path_without_query.lower().endswith(ext) for ext in js_extensions):
            # Additional validation: check if it's a reasonable JS file
            # Skip if it looks like just a library name without proper path
            if '/' in path_without_query and not path_without_query.endswith('/Node.js'):
                js_urls.append(url)
                seen_urls.add(url)
        # Also check if path contains .js even if there are query params
        elif '.js' in path_without_query.lower() and '/' in path_without_query:
            js_urls.append(url)
            seen_urls.add(url)

    return js_urls


def download_javascript_files(urls: List[str], max_files: int = 50, timeout: int = 10, verbose: bool = False) -> List[Tuple[str, str]]:
    """Download JavaScript files from URLs.

    Args:
        urls: List of JavaScript URLs to download
        max_files: Maximum number of files to download
        timeout: Timeout per request
        verbose: Show verbose output

    Returns:
        List of tuples (url, content)
    """
    results = []
    downloaded = 0
    failed = 0
    skipped = 0

    for url in urls:
        if downloaded >= max_files:
            skipped = len(urls) - (downloaded + failed)
            if verbose:
                print(f"[Download] Reached max files limit ({max_files}), skipping {skipped} remaining")
            break

        try:
            if verbose:
                print(f"[Download] Fetching: {url}")

            response = requests.get(
                url,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
                },
                allow_redirects=True
            )

            if response.status_code == 200:
                # Verify we got actual JavaScript content
                content = response.text
                if content and len(content) > 0:
                    results.append((url, content))
                    downloaded += 1
                    if verbose:
                        print(f"[Download] ✓ Downloaded ({len(content)} bytes)")
                else:
                    failed += 1
                    if verbose:
                        print(f"[Download] ✗ Empty response")
            else:
                failed += 1
                if verbose:
                    print(f"[Download] ✗ Failed with status {response.status_code}")

        except requests.exceptions.Timeout:
            failed += 1
            if verbose:
                print(f"[Download] ✗ Timeout")
        except requests.exceptions.RequestException as e:
            failed += 1
            if verbose:
                print(f"[Download] ✗ Request error: {str(e)[:50]}")
        except Exception as e:
            failed += 1
            if verbose:
                print(f"[Download] ✗ Error: {str(e)[:50]}")

    # Print summary
    if verbose and (failed > 0 or skipped > 0):
        print(f"\n[Download] Summary: {downloaded} downloaded, {failed} failed, {skipped} skipped")

    return results


def crawl_and_analyze(url: str, max_files: int = 50, timeout: int = 120, verbose: bool = False) -> Tuple[bool, List[Tuple[str, str]], Optional[str]]:
    """Crawl a website with Katana and download JavaScript files for analysis.

    Args:
        url: Target URL to crawl
        max_files: Maximum number of JS files to download
        timeout: Timeout for Katana crawling
        verbose: Show verbose output

    Returns:
        Tuple of (success, list_of_(url, content), error_message)
    """
    if verbose:
        print(f"\n[Katana] Starting crawl of {url}")
        print(f"[Katana] Max files: {max_files}, Timeout: {timeout}s")

    # Run Katana to discover URLs
    success, urls, error = crawl_with_katana(url, timeout=timeout, verbose=verbose)

    if not success:
        return False, [], error

    if not urls:
        return False, [], "No URLs discovered by Katana"

    if verbose:
        print(f"\n[Filter] Filtering {len(urls)} URLs for JavaScript files")

    # Filter for JavaScript files
    js_urls = filter_javascript_urls(urls)

    if not js_urls:
        return False, [], "No JavaScript files found in discovered URLs"

    if verbose:
        print(f"[Filter] Found {len(js_urls)} JavaScript files")
        print(f"\n[Download] Downloading up to {max_files} JavaScript files")

    # Download JavaScript files
    js_contents = download_javascript_files(js_urls, max_files=max_files, verbose=verbose)

    if not js_contents:
        return False, [], "Failed to download any JavaScript files"

    if verbose:
        print(f"\n[Download] Successfully downloaded {len(js_contents)} files")

    return True, js_contents, None


def get_unique_domains(urls: List[str]) -> List[str]:
    """Extract unique domains from a list of URLs.

    Args:
        urls: List of URLs

    Returns:
        List of unique domains
    """
    domains = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if domain:
                domains.add(domain)
        except Exception:
            continue

    return sorted(list(domains))
