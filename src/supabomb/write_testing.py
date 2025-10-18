"""Write permission testing utilities."""
import uuid
from typing import Dict, Any, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich import box


console = Console()


def generate_test_data_from_template(template: Dict[str, Any], test_id: str) -> Dict[str, Any]:
    """Generate test data based on a template row.

    Args:
        template: Sample row from table
        test_id: UUID to use for testing

    Returns:
        Dictionary of test data
    """
    test_data = {}

    for key, value in template.items():
        # Identify ID fields (primary keys or foreign keys)
        is_id_field = any(id_pattern in key.lower() for id_pattern in ['id', 'uuid', '_id', 'pk'])

        if is_id_field and key in ['id', 'uuid', 'pk']:
            # Primary key - generate new UUID
            test_data[key] = test_id
        elif is_id_field:
            # Foreign key - keep original value to maintain referential integrity
            test_data[key] = value
        elif isinstance(value, str):
            # Check if it's a timestamp/date field
            is_timestamp = any(pattern in key.lower() for pattern in ['created', 'updated', 'timestamp', '_at', 'date', 'time'])
            is_timestamp_value = value and ('T' in value or '-' in value) and len(value) > 10

            if is_timestamp or is_timestamp_value:
                # Keep timestamp fields unchanged
                test_data[key] = value
            else:
                # String field - modify last character
                if len(value) > 0:
                    test_data[key] = value[:-1] + 'X' if value[-1] != 'X' else value[:-1] + 'Y'
                else:
                    test_data[key] = 'supabomb_test'
        elif isinstance(value, (int, float)):
            # Numeric field - slightly modify
            test_data[key] = value + 1
        elif isinstance(value, bool):
            # Boolean field - flip it
            test_data[key] = not value
        elif value is None:
            # Null field - keep as None
            test_data[key] = None
        else:
            # Other types - keep original
            test_data[key] = value

    return test_data


def generate_minimal_test_data(columns: list, test_id: str) -> Dict[str, Any]:
    """Generate minimal test data with just an ID field.

    Args:
        columns: List of column names
        test_id: UUID to use for testing

    Returns:
        Dictionary with ID field
    """
    test_data = {}
    for col in ['id', 'uuid', '_id', 'pk']:
        if col in columns:
            test_data[col] = test_id
            break
    return test_data


def categorize_insert_error(insert_error: Optional[str]) -> Tuple[str, str]:
    """Categorize an insert error into status and details.

    Args:
        insert_error: Error message from insert attempt

    Returns:
        Tuple of (status, details) where status is 'allowed', 'denied', or 'possible'
    """
    if not insert_error:
        return 'denied', 'Insert failed with unknown error'

    is_rls_block = any(x in insert_error.lower() for x in ['row-level security', 'rls', 'forbidden', 'permission denied'])
    is_validation_error = any(x in insert_error.lower() for x in ['violates', 'constraint', 'null value', 'foreign key', 'unique', 'check', 'invalid input syntax', 'invalid', 'type'])

    if is_rls_block:
        # True RLS block - operation not permitted
        return 'denied', f"Insert denied by RLS: {insert_error}"
    elif is_validation_error:
        # Schema validation error - insert might be possible with proper data
        return 'possible', f"Insert possible but needs crafted data: {insert_error}"
    else:
        # Other error
        return 'denied', f"Insert failed: {insert_error}"


def find_id_field(row_data: Dict[str, Any]) -> Tuple[Optional[str], Optional[Any]]:
    """Find the ID field in a row of data.

    Args:
        row_data: Dictionary of row data

    Returns:
        Tuple of (id_field_name, id_value) or (None, None) if not found
    """
    for id_field in ['id', 'uuid', '_id', 'pk'] + list(row_data.keys()):
        if id_field in row_data:
            return id_field, row_data[id_field]
    return None, None


def create_update_data(row_data: Dict[str, Any], id_field: str, test_id: str) -> Dict[str, Any]:
    """Create update data by modifying a non-ID field.

    Args:
        row_data: Dictionary of row data
        id_field: Name of the ID field to skip
        test_id: Test UUID for fallback

    Returns:
        Dictionary with field to update
    """
    update_data = {}

    # Try to find a non-ID string field to update
    for key, value in row_data.items():
        if isinstance(value, str) and key not in [id_field] and not any(id_pattern in key.lower() for id_pattern in ['id', 'uuid', '_id', 'pk']):
            is_timestamp = any(pattern in key.lower() for pattern in ['created', 'updated', 'timestamp', '_at', 'date', 'time'])
            if not is_timestamp:
                update_data[key] = 'supabomb_updated_' + test_id[:8]
                break

    # If no string field found, try numeric
    if not update_data:
        for key, value in row_data.items():
            if isinstance(value, (int, float)) and key not in [id_field]:
                update_data[key] = value + 999
                break

    return update_data


def test_table_write_permissions(client, table_name: str, access_token: Optional[str] = None, verbose: bool = False) -> Dict[str, Any]:
    """Test INSERT, UPDATE, DELETE permissions on a table.

    Args:
        client: SupabaseClient instance
        table_name: Name of table to test
        access_token: Optional user JWT token for authenticated testing
        verbose: Show verbose output

    Returns:
        Dictionary with test results
    """
    if verbose:
        console.print(f"[dim]Testing {table_name}...[/dim]")

    test_id = str(uuid.uuid4())

    # Try to get sample data to use as template
    if access_token:
        success, sample_data, error = client.query_table_authenticated(table_name, access_token, limit=1)
    else:
        success, sample_data, error = client.query_table(table_name, limit=1)

    # Generate test data
    if success and sample_data and len(sample_data) > 0:
        test_data = generate_test_data_from_template(sample_data[0], test_id)
    else:
        columns = client.get_table_columns(table_name)
        test_data = generate_minimal_test_data(columns, test_id)

    # Test INSERT
    if access_token:
        insert_success, inserted_data, insert_error = client.test_insert_authenticated(
            table_name, access_token, test_data
        )
    else:
        insert_success, inserted_data, insert_error = client.test_insert(table_name, test_data)

    result = {
        'insert_success': insert_success,
        'update_success': False,
        'delete_success': False,
        'insert_status': 'allowed' if insert_success else 'denied',
        'details': ''
    }

    if insert_success and inserted_data:
        # Extract ID for update/delete
        if isinstance(inserted_data, list) and len(inserted_data) > 0:
            inserted_row = inserted_data[0]
        else:
            inserted_row = inserted_data

        # Find ID field
        id_field, actual_id = find_id_field(inserted_row)

        if actual_id and id_field:
            match_filter = {id_field: f'eq.{actual_id}'}

            # Test UPDATE
            update_data = create_update_data(inserted_row, id_field, test_id)

            if update_data:
                if access_token:
                    update_success, update_error = client.test_update_authenticated(
                        table_name, access_token, match_filter, update_data
                    )
                else:
                    update_success, update_error = client.test_update(table_name, match_filter, update_data)

                result['update_success'] = update_success
                if not update_success and update_error:
                    result['update_error'] = update_error

            # Test DELETE (cleanup)
            if access_token:
                delete_success, delete_error = client.test_delete_authenticated(
                    table_name, access_token, match_filter
                )
            else:
                delete_success, delete_error = client.test_delete(table_name, match_filter)

            result['delete_success'] = delete_success
            if not delete_success and delete_error:
                result['delete_error'] = delete_error

        else:
            result['details'] = "Insert succeeded but no ID field found for update/delete"
    else:
        # Categorize insert error
        status, details = categorize_insert_error(insert_error)
        result['insert_status'] = status
        result['details'] = details

    return result


def display_write_test_results(results: Dict[str, Dict[str, Any]]):
    """Display write permission test results in a table.

    Args:
        results: Dictionary mapping table names to test results
    """
    results_table = Table(title="Write Permission Test Results", box=box.ROUNDED)
    results_table.add_column("Table", style="cyan")
    results_table.add_column("INSERT", style="yellow")
    results_table.add_column("UPDATE", style="blue")
    results_table.add_column("DELETE", style="magenta")
    results_table.add_column("Details", style="white")

    for table_name, result in results.items():
        # Format results with colors
        if result['insert_success']:
            insert_result = "[green]✓[/green]"
        elif result['insert_status'] == 'possible':
            insert_result = "[yellow]⚠[/yellow]"
        else:
            insert_result = "[red]✗[/red]"

        if result['update_success']:
            update_result = "[green]✓[/green]"
        elif result.get('update_error') and any(x in result['update_error'].lower() for x in ['row-level security', 'rls', 'forbidden']):
            update_result = "[red]✗[/red]"
        elif 'update_error' in result:
            update_result = "[yellow]⚠[/yellow]"
        else:
            update_result = "[dim]-[/dim]"

        if result['delete_success']:
            delete_result = "[green]✓[/green]"
        elif result.get('delete_error') and any(x in result['delete_error'].lower() for x in ['row-level security', 'rls', 'forbidden']):
            delete_result = "[red]✗[/red]"
        elif 'delete_error' in result:
            delete_result = "[yellow]⚠[/yellow]"
        else:
            delete_result = "[dim]-[/dim]"

        results_table.add_row(table_name, insert_result, update_result, delete_result, result.get('details', ''))

    console.print("\n")
    console.print(results_table)
    console.print("\n[dim]Legend: ✓ = Allowed, ✗ = Denied (RLS), ⚠ = Possible with crafted data, - = Not tested[/dim]")
