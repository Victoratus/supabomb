"""Supabomb - Supabase Pentesting CLI Tool."""

from .cli import cli
from .client import SupabaseClient
from .discovery import SupabaseDiscovery
from .enumeration import SupabaseEnumerator
from .testing import SupabaseTester
from .models import (
    SupabaseCredentials,
    DiscoveryResult,
    TableInfo,
    RPCFunction,
    EdgeFunction,
    SecurityFinding,
    ScanResult
)

__version__ = "0.1.0"

__all__ = [
    'cli',
    'SupabaseClient',
    'SupabaseDiscovery',
    'SupabaseEnumerator',
    'SupabaseTester',
    'SupabaseCredentials',
    'DiscoveryResult',
    'TableInfo',
    'RPCFunction',
    'EdgeFunction',
    'SecurityFinding',
    'ScanResult',
]


def main():
    """Main entry point for CLI."""
    cli()
