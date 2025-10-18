"""JWT token utilities for Supabomb."""
import jwt
from typing import Optional


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
