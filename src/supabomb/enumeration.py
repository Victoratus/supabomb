"""Enumeration module for discovering Supabase resources."""
from typing import List, Optional
from .client import SupabaseClient
from .models import TableInfo, RPCFunction, EdgeFunction, SupabaseCredentials


class SupabaseEnumerator:
    """Enumerate Supabase resources."""

    def __init__(self, client: SupabaseClient):
        """Initialize enumerator.

        Args:
            client: Initialized SupabaseClient
        """
        self.client = client

    def enumerate_tables(self, sample_size: int = 5) -> List[TableInfo]:
        """Enumerate all accessible tables.

        Args:
            sample_size: Number of sample rows to fetch per table

        Returns:
            List of TableInfo objects
        """
        results = []
        table_names = self.client.list_tables()

        for table_name in table_names:
            # Get columns from schema
            columns = self.client.get_table_columns(table_name)

            # Try to query the table
            success, data, error = self.client.query_table(
                table_name,
                limit=sample_size
            )

            # Try to count rows if accessible
            row_count = None
            if success:
                row_count = self.client.count_table_rows(table_name)

            table_info = TableInfo(
                name=table_name,
                columns=columns,
                accessible=success,
                row_count=row_count,
                sample_data=data if success else None
            )

            results.append(table_info)

        return results

    def enumerate_rpc_functions(self) -> List[RPCFunction]:
        """Enumerate all accessible RPC functions.

        Returns:
            List of RPCFunction objects
        """
        results = []
        function_names = self.client.list_rpc_functions()

        for func_name in function_names:
            # Try calling with empty params
            success, response, error = self.client.call_rpc(func_name, {})

            # Extract parameters from schema if available
            schema = self.client.get_openapi_schema()
            parameters = []

            if schema:
                path_def = schema.get('paths', {}).get(f'/rpc/{func_name}', {})
                post_def = path_def.get('post', {})
                params_def = post_def.get('parameters', [])

                for param in params_def:
                    if 'name' in param:
                        parameters.append(param['name'])

            func_info = RPCFunction(
                name=func_name,
                parameters=parameters,
                accessible=success,
                response=response if success else error
            )

            results.append(func_info)

        return results

    def enumerate_edge_functions(self, function_names: Optional[List[str]] = None) -> List[EdgeFunction]:
        """Enumerate edge functions (requires function names to test).

        Args:
            function_names: List of function names to test (must be provided)

        Returns:
            List of EdgeFunction objects
        """
        if not function_names:
            return []

        results = []

        for func_name in function_names:
            # Test without auth first
            status_no_auth, requires_jwt, error = self.client.test_edge_function(
                func_name,
                with_auth=False
            )

            # Test with auth
            status_with_auth, _, _ = self.client.test_edge_function(
                func_name,
                with_auth=True
            )

            accessible_with_anon = status_with_auth in [200, 404, 500]

            func_info = EdgeFunction(
                name=func_name,
                requires_jwt=requires_jwt,
                accessible_with_anon=accessible_with_anon,
                response_code=status_with_auth
            )

            results.append(func_info)

        return results

    def enumerate_storage_buckets(self) -> List[dict]:
        """Enumerate storage buckets and test access.

        Returns:
            List of bucket information dictionaries
        """
        results = []
        success, bucket_names, error = self.client.list_storage_buckets()

        if not success or not bucket_names:
            return results

        for bucket_name in bucket_names:
            accessible, error_msg = self.client.test_bucket_access(bucket_name)

            results.append({
                'name': bucket_name,
                'accessible': accessible,
                'error': error_msg
            })

        return results

    def quick_enumerate(self) -> dict:
        """Perform quick enumeration of all resources.

        Returns:
            Dictionary with all enumerated resources
        """
        return {
            'tables': self.enumerate_tables(sample_size=1),
            'rpc_functions': self.enumerate_rpc_functions(),
            'storage_buckets': self.enumerate_storage_buckets()
        }
