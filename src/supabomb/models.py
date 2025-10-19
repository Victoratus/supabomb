"""Data models for Supabomb."""
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class SupabaseCredentials:
    """Supabase project credentials."""
    project_ref: str
    anon_key: str
    url: str

    @property
    def base_url(self) -> str:
        """Get base URL for the project."""
        return f"https://{self.project_ref}.supabase.co"


@dataclass
class DiscoveredEdgeFunction:
    """Edge function discovered from JavaScript code."""
    name: str
    args: Optional[Dict[str, Any]] = None
    raw_args: Optional[str] = None
    invocation_example: Optional[str] = None


@dataclass
class DiscoveryResult:
    """Result from discovering Supabase in a webapp."""
    found: bool
    project_ref: Optional[str] = None
    anon_key: Optional[str] = None
    url: Optional[str] = None
    source: Optional[str] = None  # Where it was found (js bundle, network, etc.)
    edge_functions: Optional[List[DiscoveredEdgeFunction]] = None

    @property
    def credentials(self) -> Optional[SupabaseCredentials]:
        """Convert to credentials if found."""
        if self.found and self.project_ref and self.anon_key and self.url:
            return SupabaseCredentials(
                project_ref=self.project_ref,
                anon_key=self.anon_key,
                url=self.url
            )
        return None


@dataclass
class TableInfo:
    """Information about a database table."""
    name: str
    columns: List[str]
    accessible: bool
    row_count: Optional[int] = None
    sample_data: Optional[List[Dict[str, Any]]] = None


@dataclass
class RPCFunction:
    """Information about an RPC function."""
    name: str
    parameters: List[str]
    accessible: bool
    response: Optional[Any] = None


@dataclass
class EdgeFunction:
    """Information about an edge function."""
    name: str
    requires_jwt: bool
    accessible_with_anon: bool
    response_code: Optional[int] = None


@dataclass
class SecurityFinding:
    """A security finding from testing."""
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    affected_resource: str
    recommendation: str
    evidence: Optional[Dict[str, Any]] = None


@dataclass
class ScanResult:
    """Complete scan result."""
    credentials: SupabaseCredentials
    tables: List[TableInfo]
    rpc_functions: List[RPCFunction]
    edge_functions: List[EdgeFunction]
    findings: List[SecurityFinding]

    @property
    def critical_findings(self) -> List[SecurityFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> List[SecurityFinding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == "high"]
