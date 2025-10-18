"""URL utilities for Supabomb."""
import re
from typing import Optional


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


def sanitize_url(url: str) -> str:
    """Sanitize URL for safe display.

    Args:
        url: URL to sanitize

    Returns:
        Sanitized URL
    """
    # Remove trailing slashes
    return url.rstrip('/')
