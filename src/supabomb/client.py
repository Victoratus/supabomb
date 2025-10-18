"""Core Supabase API client for pentesting."""
import requests
from typing import Optional, Dict, Any, List, Tuple
import json
import base64
import time
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
            # OpenAPI endpoint requires trailing slash
            response = self.session.get(
                f"{self.rest_url}/",
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
            limit: Maximum rows to return (None for all rows)
            select: Columns to select

        Returns:
            Tuple of (success, data, error_message)
        """
        try:
            params = {'select': select}
            if limit is not None:
                params['limit'] = limit

            response = self.session.get(
                f"{self.rest_url}/{table_name}",
                params=params,
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

            # PostgREST returns 206 (Partial Content) with count
            if response.status_code in [200, 206]:
                # Count is in Content-Range header (format: "0-0/20" or "*/20")
                content_range = response.headers.get('Content-Range', '')
                if '/' in content_range:
                    count_str = content_range.split('/')[-1].strip()
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

    def get_auth_settings(self) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Get authentication settings.

        Returns:
            Tuple of (success, settings_dict, error_message)
        """
        try:
            response = self.session.get(
                f"{self.auth_url}/settings",
                timeout=self.timeout
            )

            if response.status_code == 200:
                return True, response.json(), None
            else:
                return False, None, f"Status {response.status_code}"

        except Exception as e:
            return False, None, str(e)

    def signup_user(self, email: str, password: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Sign up a new user.

        Args:
            email: User email
            password: User password

        Returns:
            Tuple of (success, response_data, error_message)
        """
        try:
            response = self.session.post(
                f"{self.auth_url}/signup",
                json={
                    "email": email,
                    "password": password
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                return True, response.json(), None
            else:
                data = response.json() if response.text else {}
                error_msg = data.get('error_description') or data.get('msg') or f"Status {response.status_code}"
                return False, data, error_msg

        except Exception as e:
            return False, None, str(e)

    def login_user(self, email: str, password: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Log in a user.

        Args:
            email: User email
            password: User password

        Returns:
            Tuple of (success, response_data, error_message)
        """
        try:
            response = self.session.post(
                f"{self.auth_url}/token?grant_type=password",
                json={
                    "email": email,
                    "password": password
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                return True, response.json(), None
            else:
                data = response.json() if response.text else {}
                error_msg = data.get('error_description') or data.get('msg') or f"Status {response.status_code}"
                return False, data, error_msg

        except Exception as e:
            return False, None, str(e)

    def is_token_expired(self, access_token: str) -> bool:
        """Check if a JWT token is expired.

        Args:
            access_token: JWT access token

        Returns:
            True if expired, False otherwise
        """
        try:
            # JWT format: header.payload.signature
            parts = access_token.split('.')
            if len(parts) != 3:
                return True

            # Decode payload (add padding if needed)
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding

            decoded = base64.urlsafe_b64decode(payload)
            payload_data = json.loads(decoded)

            # Check expiration time
            exp = payload_data.get('exp')
            if not exp:
                return False

            # Add 60 second buffer to refresh before actual expiration
            return time.time() > (exp - 60)

        except Exception:
            # If we can't decode, assume expired
            return True

    def refresh_token(self, email: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Refresh an expired token by logging in again.

        Args:
            email: User email
            password: User password

        Returns:
            Tuple of (success, new_access_token, error_message)
        """
        success, response, error = self.login_user(email, password)
        if success and response:
            return True, response.get('access_token'), None
        return False, None, error

    def query_table_authenticated(self, table_name: str, access_token: str,
                                  limit: int = 10, select: str = "*") -> Tuple[bool, Optional[List[Dict]], Optional[str]]:
        """Query a table with authenticated user credentials.

        Args:
            table_name: Name of table to query
            access_token: User JWT access token
            limit: Maximum rows to return (None for all rows)
            select: Columns to select

        Returns:
            Tuple of (success, data, error_message)
        """
        try:
            # Create temporary session with user JWT
            temp_session = requests.Session()
            temp_session.headers.update({
                'apikey': self.credentials.anon_key,
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            })

            params = {'select': select}
            if limit is not None:
                params['limit'] = limit

            response = temp_session.get(
                f"{self.rest_url}/{table_name}",
                params=params,
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

    def count_table_rows_authenticated(self, table_name: str, access_token: str) -> Optional[int]:
        """Count rows in a table with authenticated user.

        Args:
            table_name: Name of table
            access_token: User JWT access token

        Returns:
            Row count or None if error
        """
        try:
            # Create temporary session with user JWT
            temp_session = requests.Session()
            temp_session.headers.update({
                'apikey': self.credentials.anon_key,
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            })

            response = temp_session.get(
                f"{self.rest_url}/{table_name}",
                params={'select': 'count'},
                headers={'Prefer': 'count=exact'},
                timeout=self.timeout
            )

            # PostgREST returns 206 (Partial Content) with count
            if response.status_code in [200, 206]:
                # Count is in Content-Range header
                content_range = response.headers.get('Content-Range', '')
                if '/' in content_range:
                    count_str = content_range.split('/')[-1].strip()
                    if count_str.isdigit():
                        return int(count_str)
            return None
        except Exception:
            return None

    def test_insert(self, table_name: str, data: Dict[str, Any]) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Test if anonymous user can insert data into a table.

        Args:
            table_name: Name of table to test
            data: Data to insert

        Returns:
            Tuple of (success, inserted_data, error_message)
        """
        try:
            response = self.session.post(
                f"{self.rest_url}/{table_name}",
                json=data,
                headers={'Prefer': 'return=representation'},
                timeout=self.timeout
            )

            if response.status_code == 201:
                return True, response.json(), None
            elif response.status_code == 403:
                return False, None, "Insert forbidden (RLS blocking access)"
            elif response.status_code == 404:
                return False, None, "Table not found"
            else:
                code, message = parse_postgrest_error(response.text)
                return False, None, message or f"Error {response.status_code}"

        except Exception as e:
            return False, None, str(e)

    def test_insert_authenticated(self, table_name: str, access_token: str,
                                   data: Dict[str, Any]) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Test if authenticated user can insert data into a table.

        Args:
            table_name: Name of table to test
            access_token: User JWT access token
            data: Data to insert

        Returns:
            Tuple of (success, inserted_data, error_message)
        """
        try:
            temp_session = requests.Session()
            temp_session.headers.update({
                'apikey': self.credentials.anon_key,
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            })

            response = temp_session.post(
                f"{self.rest_url}/{table_name}",
                json=data,
                headers={'Prefer': 'return=representation'},
                timeout=self.timeout
            )

            if response.status_code == 201:
                return True, response.json(), None
            elif response.status_code == 403:
                return False, None, "Insert forbidden (RLS blocking access)"
            elif response.status_code == 404:
                return False, None, "Table not found"
            else:
                code, message = parse_postgrest_error(response.text)
                return False, None, message or f"Error {response.status_code}"

        except Exception as e:
            return False, None, str(e)

    def test_delete(self, table_name: str, match_filter: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Test if anonymous user can delete data from a table.

        Args:
            table_name: Name of table to test
            match_filter: Filter to identify rows to delete (e.g., {'id': 'eq.123'})

        Returns:
            Tuple of (success, error_message)
        """
        try:
            response = self.session.delete(
                f"{self.rest_url}/{table_name}",
                params=match_filter,
                timeout=self.timeout
            )

            if response.status_code in [200, 204]:
                return True, None
            elif response.status_code == 403:
                return False, "Delete forbidden (RLS blocking access)"
            elif response.status_code == 404:
                return False, "Table not found or no matching rows"
            else:
                code, message = parse_postgrest_error(response.text)
                return False, message or f"Error {response.status_code}"

        except Exception as e:
            return False, str(e)

    def test_delete_authenticated(self, table_name: str, access_token: str,
                                   match_filter: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Test if authenticated user can delete data from a table.

        Args:
            table_name: Name of table to test
            access_token: User JWT access token
            match_filter: Filter to identify rows to delete (e.g., {'id': 'eq.123'})

        Returns:
            Tuple of (success, error_message)
        """
        try:
            temp_session = requests.Session()
            temp_session.headers.update({
                'apikey': self.credentials.anon_key,
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            })

            response = temp_session.delete(
                f"{self.rest_url}/{table_name}",
                params=match_filter,
                timeout=self.timeout
            )

            if response.status_code in [200, 204]:
                return True, None
            elif response.status_code == 403:
                return False, "Delete forbidden (RLS blocking access)"
            elif response.status_code == 404:
                return False, "Table not found or no matching rows"
            else:
                code, message = parse_postgrest_error(response.text)
                return False, message or f"Error {response.status_code}"

        except Exception as e:
            return False, str(e)

    def test_update(self, table_name: str, match_filter: Dict[str, Any],
                    data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Test if anonymous user can update data in a table.

        Args:
            table_name: Name of table to test
            match_filter: Filter to identify rows to update (e.g., {'id': 'eq.123'})
            data: Data to update

        Returns:
            Tuple of (success, error_message)
        """
        try:
            response = self.session.patch(
                f"{self.rest_url}/{table_name}",
                params=match_filter,
                json=data,
                timeout=self.timeout
            )

            if response.status_code in [200, 204]:
                return True, None
            elif response.status_code == 403:
                return False, "Update forbidden (RLS blocking access)"
            elif response.status_code == 404:
                return False, "Table not found or no matching rows"
            else:
                code, message = parse_postgrest_error(response.text)
                return False, message or f"Error {response.status_code}"

        except Exception as e:
            return False, str(e)

    def test_update_authenticated(self, table_name: str, access_token: str,
                                   match_filter: Dict[str, Any],
                                   data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Test if authenticated user can update data in a table.

        Args:
            table_name: Name of table to test
            access_token: User JWT access token
            match_filter: Filter to identify rows to update (e.g., {'id': 'eq.123'})
            data: Data to update

        Returns:
            Tuple of (success, error_message)
        """
        try:
            temp_session = requests.Session()
            temp_session.headers.update({
                'apikey': self.credentials.anon_key,
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            })

            response = temp_session.patch(
                f"{self.rest_url}/{table_name}",
                params=match_filter,
                json=data,
                timeout=self.timeout
            )

            if response.status_code in [200, 204]:
                return True, None
            elif response.status_code == 403:
                return False, "Update forbidden (RLS blocking access)"
            elif response.status_code == 404:
                return False, "Table not found or no matching rows"
            else:
                code, message = parse_postgrest_error(response.text)
                return False, message or f"Error {response.status_code}"

        except Exception as e:
            return False, str(e)
