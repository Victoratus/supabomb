"""Security testing module for Supabase instances."""
from typing import List
from .client import SupabaseClient
from .enumeration import SupabaseEnumerator
from .models import SecurityFinding, TableInfo, RPCFunction


class SupabaseTester:
    """Perform security tests on Supabase instances."""

    def __init__(self, client: SupabaseClient):
        """Initialize tester.

        Args:
            client: Initialized SupabaseClient
        """
        self.client = client
        self.enumerator = SupabaseEnumerator(client)

    def test_rls_policies(self) -> List[SecurityFinding]:
        """Test for missing or weak RLS policies.

        Returns:
            List of security findings
        """
        findings = []
        tables = self.enumerator.enumerate_tables(sample_size=1)

        for table in tables:
            if table.accessible and table.sample_data:
                # Table is accessible with anon key - check if data is returned
                if len(table.sample_data) > 0:
                    findings.append(SecurityFinding(
                        severity="high",
                        title=f"Table '{table.name}' accessible with anonymous key",
                        description=(
                            f"The table '{table.name}' returns data when queried with "
                            f"the anonymous API key. This may indicate missing or "
                            f"misconfigured Row Level Security (RLS) policies."
                        ),
                        affected_resource=f"Table: {table.name}",
                        recommendation=(
                            "Enable RLS on this table and create appropriate policies "
                            "to restrict anonymous access. Use: "
                            f"ALTER TABLE {table.name} ENABLE ROW LEVEL SECURITY;"
                        ),
                        evidence={
                            'table': table.name,
                            'columns': table.columns,
                            'row_count': table.row_count,
                            'sample_data': table.sample_data[:2]  # Show first 2 rows
                        }
                    ))

        return findings

    def test_authentication_config(self) -> List[SecurityFinding]:
        """Test authentication configuration.

        Returns:
            List of security findings
        """
        findings = []

        # Test if signup is enabled
        signup_enabled, message = self.client.test_signup_enabled()

        if signup_enabled:
            findings.append(SecurityFinding(
                severity="medium",
                title="Anonymous signup is enabled",
                description=(
                    "The Supabase instance allows anonymous users to create accounts. "
                    "This may be intentional, but could also lead to abuse if not "
                    "properly configured with email confirmation and rate limiting."
                ),
                affected_resource="Auth API",
                recommendation=(
                    "Review signup configuration. Consider:\n"
                    "- Enabling email confirmation\n"
                    "- Implementing rate limiting\n"
                    "- Adding CAPTCHA protection\n"
                    "- Requiring manual approval for new accounts"
                ),
                evidence={'message': message}
            ))

        return findings

    def test_rpc_functions(self) -> List[SecurityFinding]:
        """Test RPC function access controls.

        Returns:
            List of security findings
        """
        findings = []
        functions = self.enumerator.enumerate_rpc_functions()

        for func in functions:
            if func.accessible:
                findings.append(SecurityFinding(
                    severity="medium",
                    title=f"RPC function '{func.name}' accessible with anonymous key",
                    description=(
                        f"The RPC function '{func.name}' can be called with the "
                        f"anonymous API key. Verify that this function doesn't "
                        f"perform sensitive operations or return sensitive data."
                    ),
                    affected_resource=f"RPC: {func.name}",
                    recommendation=(
                        "Review the function's logic and ensure it:\n"
                        "- Checks user authentication if needed\n"
                        "- Validates all input parameters\n"
                        "- Uses SECURITY DEFINER with caution\n"
                        "- Has appropriate RLS policies if accessing tables"
                    ),
                    evidence={
                        'function': func.name,
                        'parameters': func.parameters,
                        'response': func.response
                    }
                ))

        return findings

    def test_storage_buckets(self) -> List[SecurityFinding]:
        """Test storage bucket access controls.

        Returns:
            List of security findings
        """
        findings = []
        buckets = self.enumerator.enumerate_storage_buckets()

        for bucket in buckets:
            if bucket['accessible']:
                findings.append(SecurityFinding(
                    severity="medium",
                    title=f"Storage bucket '{bucket['name']}' is accessible",
                    description=(
                        f"The storage bucket '{bucket['name']}' can be listed with "
                        f"the anonymous API key. Verify that this bucket should be "
                        f"publicly accessible."
                    ),
                    affected_resource=f"Bucket: {bucket['name']}",
                    recommendation=(
                        "Review bucket policies:\n"
                        "- Make bucket private if it contains sensitive files\n"
                        "- Implement RLS policies for fine-grained access control\n"
                        "- Use signed URLs for temporary access\n"
                        "- Audit bucket contents regularly"
                    ),
                    evidence=bucket
                ))

        return findings

    def test_edge_functions(self, function_names: List[str]) -> List[SecurityFinding]:
        """Test edge function authentication requirements.

        Args:
            function_names: List of function names to test

        Returns:
            List of security findings
        """
        findings = []
        functions = self.enumerator.enumerate_edge_functions(function_names)

        for func in functions:
            if not func.requires_jwt and func.accessible_with_anon:
                findings.append(SecurityFinding(
                    severity="info",
                    title=f"Edge function '{func.name}' doesn't require JWT",
                    description=(
                        f"The edge function '{func.name}' can be accessed without "
                        f"authentication. This may be intentional (e.g., for webhooks "
                        f"or public APIs), but verify this is the expected behavior."
                    ),
                    affected_resource=f"Edge Function: {func.name}",
                    recommendation=(
                        "If authentication is required:\n"
                        "- Add JWT verification in function code\n"
                        "- Use Supabase client with user context\n"
                        "- Implement custom authentication logic if needed\n"
                        "If public access is intentional, document this decision."
                    ),
                    evidence={
                        'function': func.name,
                        'requires_jwt': func.requires_jwt,
                        'response_code': func.response_code
                    }
                ))

        return findings

    def run_all_tests(self, edge_function_names: List[str] = None) -> List[SecurityFinding]:
        """Run all security tests.

        Args:
            edge_function_names: Optional list of edge function names to test

        Returns:
            List of all security findings
        """
        findings = []

        # Test RLS
        findings.extend(self.test_rls_policies())

        # Test authentication
        findings.extend(self.test_authentication_config())

        # Test RPC functions
        findings.extend(self.test_rpc_functions())

        # Test storage buckets
        findings.extend(self.test_storage_buckets())

        # Test edge functions if names provided
        if edge_function_names:
            findings.extend(self.test_edge_functions(edge_function_names))

        return findings

    def generate_report(self, findings: List[SecurityFinding]) -> dict:
        """Generate a summary report of findings.

        Args:
            findings: List of security findings

        Returns:
            Report dictionary
        """
        critical = [f for f in findings if f.severity == "critical"]
        high = [f for f in findings if f.severity == "high"]
        medium = [f for f in findings if f.severity == "medium"]
        low = [f for f in findings if f.severity == "low"]
        info = [f for f in findings if f.severity == "info"]

        return {
            'total_findings': len(findings),
            'by_severity': {
                'critical': len(critical),
                'high': len(high),
                'medium': len(medium),
                'low': len(low),
                'info': len(info)
            },
            'findings': findings,
            'risk_score': (
                len(critical) * 10 +
                len(high) * 5 +
                len(medium) * 2 +
                len(low) * 1
            )
        }
