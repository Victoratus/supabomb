"""Web discovery module for finding Supabase instances."""
import requests
from bs4 import BeautifulSoup
from typing import Optional, List, Dict
import re
from .models import DiscoveryResult, DiscoveredEdgeFunction
from .url_utils import extract_supabase_url, extract_project_ref
from .extraction_utils import extract_jwt_from_text
from .jwt_utils import is_supabase_anon_key
from .edge_function_parser import extract_edge_functions, extract_edge_function_examples
from .katana_integration import crawl_and_analyze


class SupabaseDiscovery:
    """Discover Supabase instances in web applications."""

    def __init__(self, timeout: int = 30, user_agent: Optional[str] = None):
        """Initialize discovery.

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom user agent string
        """
        self.timeout = timeout
        self.session = requests.Session()

        if user_agent:
            self.session.headers['User-Agent'] = user_agent
        else:
            self.session.headers['User-Agent'] = (
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            )

    def discover_from_url(self, url: str) -> DiscoveryResult:
        """Discover Supabase from a web URL.

        Args:
            url: Target URL to analyze

        Returns:
            DiscoveryResult with findings
        """
        try:
            # First, try to get the HTML page
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            html_content = response.text

            # Parse HTML to find JavaScript sources
            soup = BeautifulSoup(html_content, 'html.parser')

            # Check inline scripts first
            for script in soup.find_all('script'):
                if script.string:
                    result = self._analyze_javascript(script.string, "inline script")
                    if result.found:
                        return result

            # Check external JavaScript files
            js_urls = []
            for script in soup.find_all('script', src=True):
                js_url = script['src']
                # Make absolute URL
                if js_url.startswith('//'):
                    js_url = 'https:' + js_url
                elif js_url.startswith('/'):
                    from urllib.parse import urljoin
                    js_url = urljoin(url, js_url)
                elif not js_url.startswith('http'):
                    from urllib.parse import urljoin
                    js_url = urljoin(url, js_url)

                js_urls.append(js_url)

            # Analyze JavaScript files
            for js_url in js_urls:
                try:
                    js_response = self.session.get(js_url, timeout=self.timeout)
                    if js_response.status_code == 200:
                        result = self._analyze_javascript(
                            js_response.text,
                            f"external script: {js_url}"
                        )
                        if result.found:
                            return result
                except Exception:
                    continue

            # Also check the HTML itself for embedded config
            result = self._analyze_javascript(html_content, "HTML content")
            if result.found:
                return result

            return DiscoveryResult(found=False)

        except Exception as e:
            return DiscoveryResult(found=False)

    def discover_from_javascript(self, js_content: str) -> DiscoveryResult:
        """Discover Supabase from JavaScript content.

        Args:
            js_content: JavaScript code content

        Returns:
            DiscoveryResult with findings
        """
        return self._analyze_javascript(js_content, "provided JavaScript")

    def _analyze_javascript(self, content: str, source: str) -> DiscoveryResult:
        """Analyze JavaScript content for Supabase credentials.

        Args:
            content: JavaScript content
            source: Description of source

        Returns:
            DiscoveryResult with findings
        """
        # Always extract edge functions first (regardless of credentials)
        edge_functions_data = extract_edge_functions(content)
        edge_function_examples = dict(extract_edge_function_examples(content))

        # Convert to DiscoveredEdgeFunction objects
        discovered_edge_functions = []
        for func_data in edge_functions_data:
            func_name = func_data['name']
            discovered_edge_functions.append(
                DiscoveredEdgeFunction(
                    name=func_name,
                    args=func_data.get('args'),
                    raw_args=func_data.get('raw_args'),
                    invocation_example=edge_function_examples.get(func_name)
                )
            )

        # Look for Supabase URL
        supabase_url = extract_supabase_url(content)

        if not supabase_url:
            # No credentials, but may have edge functions
            if discovered_edge_functions:
                return DiscoveryResult(
                    found=False,
                    edge_functions=discovered_edge_functions
                )
            return DiscoveryResult(found=False)

        project_ref = extract_project_ref(supabase_url)

        # Look for anon key (JWT token)
        anon_key = None

        # Common patterns for finding the anon key
        patterns = [
            # Direct variable assignment
            r'["\']([^"\']*eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["\']',
            # In createClient calls
            r'createClient\s*\([^,]+,\s*["\']([^"\']+)["\']',
            # Environment variables
            r'SUPABASE_ANON_KEY["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'NEXT_PUBLIC_SUPABASE_ANON_KEY["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'VITE_SUPABASE_ANON_KEY["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'REACT_APP_SUPABASE_ANON_KEY["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Verify it's a Supabase anon key
                if is_supabase_anon_key(match):
                    anon_key = match
                    break
            if anon_key:
                break

        # If pattern matching failed, try generic JWT extraction
        if not anon_key:
            potential_jwt = extract_jwt_from_text(content)
            if potential_jwt and is_supabase_anon_key(potential_jwt):
                anon_key = potential_jwt

        if anon_key:
            return DiscoveryResult(
                found=True,
                project_ref=project_ref,
                anon_key=anon_key,
                url=supabase_url,
                source=source,
                edge_functions=discovered_edge_functions if discovered_edge_functions else None
            )

        # Found URL but no key
        return DiscoveryResult(
            found=True,
            project_ref=project_ref,
            anon_key=None,
            url=supabase_url,
            source=source,
            edge_functions=discovered_edge_functions if discovered_edge_functions else None
        )

    def discover_from_network_traffic(self, har_file: str) -> List[DiscoveryResult]:
        """Discover Supabase from HAR (HTTP Archive) file.

        Args:
            har_file: Path to HAR file

        Returns:
            List of DiscoveryResults found
        """
        results = []

        try:
            import json
            with open(har_file, 'r') as f:
                har_data = json.load(f)

            entries = har_data.get('log', {}).get('entries', [])

            for entry in entries:
                request = entry.get('request', {})
                url = request.get('url', '')

                # Check if this is a Supabase request
                if '.supabase.co' in url:
                    project_ref = extract_project_ref(url)
                    if not project_ref:
                        continue

                    # Look for API key in headers
                    anon_key = None
                    headers = request.get('headers', [])

                    for header in headers:
                        name = header.get('name', '').lower()
                        value = header.get('value', '')

                        if name in ['apikey', 'authorization']:
                            # Extract JWT from Authorization header
                            if value.startswith('Bearer '):
                                value = value[7:]

                            if is_supabase_anon_key(value):
                                anon_key = value
                                break

                    if anon_key:
                        # Check if we already have this result
                        existing = any(
                            r.project_ref == project_ref and r.anon_key == anon_key
                            for r in results
                        )

                        if not existing:
                            results.append(DiscoveryResult(
                                found=True,
                                project_ref=project_ref,
                                anon_key=anon_key,
                                url=f"https://{project_ref}.supabase.co",
                                source=f"HAR network traffic: {url}"
                            ))

        except Exception:
            pass

        return results

    def discover_from_file(self, file_path: str) -> DiscoveryResult:
        """Discover Supabase credentials from a file.

        Args:
            file_path: Path to file (JS, HTML, env, etc.)

        Returns:
            DiscoveryResult with findings
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            return self._analyze_javascript(content, f"file: {file_path}")

        except Exception:
            return DiscoveryResult(found=False)

    def discover_with_katana(self, url: str, max_files: int = 50, timeout: int = 120, verbose: bool = False) -> DiscoveryResult:
        """Discover Supabase using Katana web crawler.

        This method uses Katana to crawl the website, extract all JavaScript files,
        and analyze them for Supabase credentials and edge functions.

        Args:
            url: Target URL to crawl
            max_files: Maximum number of JS files to download and analyze
            timeout: Timeout for Katana crawling
            verbose: Show verbose output

        Returns:
            Aggregated DiscoveryResult with findings from all JS files
        """
        # Use Katana to crawl and download JS files
        success, js_files, error = crawl_and_analyze(
            url,
            max_files=max_files,
            timeout=timeout,
            verbose=verbose
        )

        if not success:
            return DiscoveryResult(found=False)

        # Analyze all JS files and collect ALL results (including edge functions only)
        all_results = []
        for file_url, content in js_files:
            result = self._analyze_javascript(content, f"Katana: {file_url}")
            # Include results with credentials OR edge functions
            if result.found or result.edge_functions:
                all_results.append(result)

        if not all_results:
            return DiscoveryResult(found=False)

        # Aggregate results (will combine credentials and edge functions)
        return self._aggregate_results(all_results, f"Katana crawl of {url}")

    def _aggregate_results(self, results: List[DiscoveryResult], source: str) -> DiscoveryResult:
        """Aggregate multiple discovery results into one.

        Args:
            results: List of DiscoveryResult objects
            source: Description of aggregated source

        Returns:
            Aggregated DiscoveryResult
        """
        if not results:
            return DiscoveryResult(found=False)

        # Take the first complete result for credentials
        main_result = None
        has_credentials = False

        for result in results:
            if result.project_ref and result.anon_key:
                main_result = result
                has_credentials = True
                break

        # If no complete result, take first with URL
        if not main_result:
            for result in results:
                if result.project_ref:
                    main_result = result
                    has_credentials = True
                    break

        # Aggregate all edge functions (deduplicate by name)
        all_edge_functions: Dict[str, DiscoveredEdgeFunction] = {}

        for result in results:
            if result.edge_functions:
                for func in result.edge_functions:
                    # Keep the one with most information
                    if func.name not in all_edge_functions:
                        all_edge_functions[func.name] = func
                    else:
                        existing = all_edge_functions[func.name]
                        # Update if new one has more info
                        if func.args and not existing.args:
                            all_edge_functions[func.name] = func
                        elif func.invocation_example and not existing.invocation_example:
                            all_edge_functions[func.name] = func

        # Create aggregated result
        edge_functions_list = list(all_edge_functions.values()) if all_edge_functions else None

        # Return result based on what we found
        if has_credentials:
            # Found credentials (and possibly edge functions)
            return DiscoveryResult(
                found=True,
                project_ref=main_result.project_ref,
                anon_key=main_result.anon_key,
                url=main_result.url,
                source=source,
                edge_functions=edge_functions_list
            )
        elif edge_functions_list:
            # Only found edge functions, no credentials
            return DiscoveryResult(
                found=True,
                project_ref=None,
                anon_key=None,
                url=None,
                source=source,
                edge_functions=edge_functions_list
            )
        else:
            # Found nothing
            return DiscoveryResult(found=False)
