"""Utility functions for Supabomb."""
import re
import base64
import json
from typing import Optional, Tuple
import jwt


def extract_supabase_url(text: str) -> Optional[str]:
    """Extract Supabase project URL from text.

    Args:
        text: Text content to search

    Returns:
        Supabase URL if found, None otherwise
    """
    pattern = r'https://([a-z0-9]+)\.supabase\.co'
    match = re.search(pattern, text)
    return match.group(0) if match else None


def extract_project_ref(url: str) -> Optional[str]:
    """Extract project reference from Supabase URL.

    Args:
        url: Supabase URL

    Returns:
        Project reference if valid URL, None otherwise
    """
    pattern = r'https://([a-z0-9]+)\.supabase\.co'
    match = re.search(pattern, url)
    return match.group(1) if match else None


def is_jwt_token(token: str) -> bool:
    """Check if a string is a JWT token.

    Args:
        token: String to check

    Returns:
        True if token appears to be JWT, False otherwise
    """
    if not token or len(token) < 100:
        return False

    parts = token.split('.')
    if len(parts) != 3:
        return False

    # Check if starts with typical JWT header
    return token.startswith('eyJ')


def decode_jwt(token: str, verify: bool = False) -> Optional[dict]:
    """Decode a JWT token without verification.

    Args:
        token: JWT token to decode
        verify: Whether to verify signature (default False for inspection)

    Returns:
        Decoded JWT payload or None if invalid
    """
    try:
        return jwt.decode(token, options={"verify_signature": verify})
    except Exception:
        return None


def is_supabase_anon_key(token: str) -> bool:
    """Check if a JWT token is a Supabase anon key.

    Args:
        token: JWT token to check

    Returns:
        True if token is Supabase anon key, False otherwise
    """
    if not is_jwt_token(token):
        return False

    payload = decode_jwt(token)
    if not payload:
        return False

    return (
        payload.get('iss') == 'supabase' and
        payload.get('role') == 'anon'
    )


def is_supabase_service_role_key(token: str) -> bool:
    """Check if a JWT token is a Supabase service role key.

    Args:
        token: JWT token to check

    Returns:
        True if token is Supabase service role key, False otherwise
    """
    if not is_jwt_token(token):
        return False

    payload = decode_jwt(token)
    if not payload:
        return False

    return (
        payload.get('iss') == 'supabase' and
        payload.get('role') == 'service_role'
    )


def extract_jwt_from_text(text: str) -> Optional[str]:
    """Extract JWT token from text content.

    Args:
        text: Text to search

    Returns:
        JWT token if found, None otherwise
    """
    # Look for JWT pattern (three base64 parts separated by dots)
    pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    matches = re.findall(pattern, text)

    for match in matches:
        if is_jwt_token(match):
            return match

    return None


def format_table_output(data: list, headers: list) -> str:
    """Format data as a simple table.

    Args:
        data: List of rows
        headers: Column headers

    Returns:
        Formatted table string
    """
    if not data:
        return "No data"

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Build table
    lines = []

    # Header
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    lines.append(header_line)
    lines.append("-" * len(header_line))

    # Data rows
    for row in data:
        line = " | ".join(str(cell).ljust(w) for cell, w in zip(row, widths))
        lines.append(line)

    return "\n".join(lines)


def sanitize_url(url: str) -> str:
    """Sanitize URL for safe display.

    Args:
        url: URL to sanitize

    Returns:
        Sanitized URL
    """
    # Remove trailing slashes
    return url.rstrip('/')


def parse_postgrest_error(response_text: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse PostgREST error response.

    Args:
        response_text: Response body

    Returns:
        Tuple of (error_code, error_message)
    """
    try:
        data = json.loads(response_text)
        return data.get('code'), data.get('message')
    except Exception:
        return None, response_text
