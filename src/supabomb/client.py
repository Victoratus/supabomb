"""Core Supabase API client for pentesting."""
import requests
from typing import Optional, Dict, Any, List, Tuple
import json
from .models import SupabaseCredentials, TableInfo, RPCFunction, EdgeFunction
from .utils import parse_postgrest_error


class SupabaseClient:
    """Client for interacting with Supabase API."""

    def __init__(self, credentials: SupabaseCredentials, timeout: int = 30):
        """Initialize Supabase client.

        Args:
            credentials: Supabase credentials
            timeout: Request timeout in seconds
        """
        self.credentials = credentials
        self.timeout = timeout
        self.session = requests.Session()

        # Set default headers
        self.session.headers.update({
            'apikey': credentials.anon_key,
            'Authorization': f'Bearer {credentials.anon_key}',
            'Content-Type': 'application/json'
        })

    @property
    def rest_url(self) -> str:
        """Get REST API base URL."""
        return f"{self.credentials.base_url}/rest/v1"

    @property
    def auth_url(self) -> str:
        """Get Auth API base URL."""
        return f"{self.credentials.base_url}/auth/v1"

    @property
    def storage_url(self) -> str:
        """Get Storage API base URL."""
        return f"{self.credentials.base_url}/storage/v1"

    @property
    def functions_url(self) -> str:
        """Get Edge Functions base URL."""
        return f"{self.credentials.base_url}/functions/v1"

    def test_connection(self) -> Tuple[bool, Optional[str]]:
        """Test connection to Supabase instance.

        Returns:
            Tuple of (success, error_message)
        """
        try:
            response = self.session.get(
                self.rest_url,
                timeout=self.timeout
            )
            if response.status_code in [200, 404]:
                return True, None
            return False, f"Unexpected status code: {response.status_code}"
        except Exception as e:
            return False, str(e)

    def get_openapi_schema(self) -> Optional[Dict[str, Any]]:
        """Fetch OpenAPI schema for the project.

        Returns:
            OpenAPI schema dictionary or None if error
        """
        try:
            response = self.session.get(
                self.rest_url,
                headers={'Accept': 'application/openapi+json'},
                timeout=self.timeout
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def list_tables(self) -> List[str]:
        """List all accessible tables from OpenAPI schema.

        Returns:
            List of table names
        """
        schema = self.get_openapi_schema()
        if not schema:
            return []

        tables = []
        paths = schema.get('paths', {})

        for path in paths.keys():
            # Skip RPC endpoints and root
            if path.startswith('/rpc/') or path == '/':
                continue
            # Remove leading slash to get table name
            table_name = path.lstrip('/')
            tables.append(table_name)

        return sorted(tables)

    def list_rpc_functions(self) -> List[str]:
        """List all RPC functions from OpenAPI schema.

        Returns:
            List of RPC function names
        """
        schema = self.get_openapi_schema()
        if not schema:
            return []

        functions = []
        paths = schema.get('paths', {})

        for path in paths.keys():
            if path.startswith('/rpc/'):
                # Extract function name after /rpc/
                func_name = path.replace('/rpc/', '')
                functions.append(func_name)

        return sorted(functions)

    def get_table_columns(self, table_name: str) -> List[str]:
        """Get column names for a table from OpenAPI schema.

        Args:
            table_name: Name of the table

        Returns:
            List of column names
        """
        schema = self.get_openapi_schema()
        if not schema:
            return []

        definitions = schema.get('definitions', {})
        table_def = definitions.get(table_name, {})
        properties = table_def.get('properties', {})

        return sorted(properties.keys())

    def query_table(self, table_name: str, limit: int = 10,
                   select: str = "*") -> Tuple[bool, Optional[List[Dict]], Optional[str]]:
        """Query a table with anonymous credentials.

        Args:
            table_name: Name of table to query
            limit: Maximum rows to return
            select: Columns to select

        Returns:
            Tuple of (success, data, error_message)
        """
        try:
            response = self.session.get(
                f"{self.rest_url}/{table_name}",
                params={'select': select, 'limit': limit},
                timeout=self.timeout
            )

            if response.status_code == 200:
                return True, response.json(), None
            elif response.status_code == 403:
                return False, None, "Access forbidden (RLS blocking access)"
            elif response.status_code == 404:
                return False, None, "Table not found or no permissions"
            else:
                code, message = parse_postgrest_error(response.text)
                return False, None, message or f"Error {response.status_code}"

        except Exception as e:
            return False, None, str(e)

    def count_table_rows(self, table_name: str) -> Optional[int]:
        """Count rows in a table.

        Args:
            table_name: Name of table

        Returns:
            Row count or None if error
        """
        try:
            response = self.session.get(
                f"{self.rest_url}/{table_name}",
                params={'select': 'count'},
                headers={'Prefer': 'count=exact'},
                timeout=self.timeout
            )

            if response.status_code == 200:
                # Count is in Content-Range header
                content_range = response.headers.get('Content-Range', '')
                if '/' in content_range:
                    count_str = content_range.split('/')[-1]
                    if count_str.isdigit():
                        return int(count_str)
            return None
        except Exception:
            return None

    def call_rpc(self, function_name: str,
                 params: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[Any], Optional[str]]:
        """Call an RPC function.

        Args:
            function_name: Name of RPC function
            params: Function parameters

        Returns:
            Tuple of (success, response_data, error_message)
        """
        try:
            response = self.session.post(
                f"{self.rest_url}/rpc/{function_name}",
                json=params or {},
                timeout=self.timeout
            )

            if response.status_code == 200:
                return True, response.json(), None
            elif response.status_code == 403:
                return False, None, "Access forbidden"
            elif response.status_code == 404:
                return False, None, "Function not found or no permissions"
            else:
                code, message = parse_postgrest_error(response.text)
                return False, None, message or f"Error {response.status_code}"

        except Exception as e:
            return False, None, str(e)

    def test_edge_function(self, function_name: str,
                          with_auth: bool = True) -> Tuple[int, bool, Optional[str]]:
        """Test if an edge function requires JWT authentication.

        Args:
            function_name: Name of edge function
            with_auth: Whether to include auth header

        Returns:
            Tuple of (status_code, requires_jwt, error_message)
        """
        try:
            headers = {}
            if not with_auth:
                # Remove auth headers for this request
                headers['Authorization'] = ''
                headers['apikey'] = ''

            response = self.session.post(
                f"{self.functions_url}/{function_name}",
                headers=headers if not with_auth else None,
                json={},
                timeout=self.timeout
            )

            # 401 = Unauthorized (JWT required)
            # 403 = Forbidden (JWT valid but insufficient permissions)
            # 404 = Not found
            # 200 = Success
            # Other = Function error

            requires_jwt = response.status_code == 401 if not with_auth else False

            return response.status_code, requires_jwt, None

        except Exception as e:
            return 0, False, str(e)

    def test_signup_enabled(self) -> Tuple[bool, Optional[str]]:
        """Test if anonymous signup is enabled.

        Returns:
            Tuple of (enabled, error_message)
        """
        try:
            # Try to sign up with a test email
            test_email = "test_supabomb_check@example.com"
            test_password = "TestPassword123!@#"

            response = self.session.post(
                f"{self.auth_url}/signup",
                json={
                    'email': test_email,
                    'password': test_password
                },
                timeout=self.timeout
            )

            # 200 = Signup successful (enabled)
            # 400 = Likely "Email already registered" or validation error
            # 403 = Signups disabled
            # 422 = Validation error

            if response.status_code == 200:
                return True, "Signups enabled and email confirmation not required"
            elif response.status_code == 400:
                error_data = response.json()
                if 'already registered' in str(error_data).lower():
                    return True, "Signups enabled (email already exists)"
                return True, f"Signups enabled: {error_data}"
            elif response.status_code == 403:
                return False, "Signups disabled"
            else:
                return False, f"Status: {response.status_code}"

        except Exception as e:
            return False, str(e)

    def list_storage_buckets(self) -> Tuple[bool, Optional[List[str]], Optional[str]]:
        """List storage buckets.

        Returns:
            Tuple of (success, bucket_names, error_message)
        """
        try:
            response = self.session.get(
                f"{self.storage_url}/bucket",
                timeout=self.timeout
            )

            if response.status_code == 200:
                buckets = response.json()
                names = [b.get('name') for b in buckets if 'name' in b]
                return True, names, None
            else:
                return False, None, f"Error {response.status_code}"

        except Exception as e:
            return False, None, str(e)

    def test_bucket_access(self, bucket_name: str) -> Tuple[bool, Optional[str]]:
        """Test if a bucket is publicly accessible.

        Args:
            bucket_name: Name of bucket to test

        Returns:
            Tuple of (accessible, error_message)
        """
        try:
            response = self.session.get(
                f"{self.storage_url}/object/list/{bucket_name}",
                timeout=self.timeout
            )

            if response.status_code == 200:
                return True, None
            elif response.status_code == 403:
                return False, "Access forbidden"
            elif response.status_code == 404:
                return False, "Bucket not found"
            else:
                return False, f"Status {response.status_code}"

        except Exception as e:
            return False, str(e)
