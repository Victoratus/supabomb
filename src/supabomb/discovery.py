"""Web discovery module for finding Supabase instances."""
import requests
from bs4 import BeautifulSoup
from typing import Optional, List
import re
from .models import DiscoveryResult
from .url_utils import extract_supabase_url, extract_project_ref
from .extraction_utils import extract_jwt_from_text
from .jwt_utils import is_supabase_anon_key


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
        # Look for Supabase URL
        supabase_url = extract_supabase_url(content)

        if not supabase_url:
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
                source=source
            )

        # Found URL but no key
        return DiscoveryResult(
            found=True,
            project_ref=project_ref,
            anon_key=None,
            url=supabase_url,
            source=source
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
