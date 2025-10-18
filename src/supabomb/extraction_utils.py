"""Data extraction utilities for Supabomb."""
import re
import json
from typing import Optional, Tuple
from .jwt_utils import is_jwt_token


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
