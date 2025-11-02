"""CLI interface for Supabomb."""
import click
import json
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box

from .discovery import SupabaseDiscovery
from .client import SupabaseClient
from .enumeration import SupabaseEnumerator
from .testing import SupabaseTester
from .models import SupabaseCredentials
from .cache import CredentialCache
from .output_formatting import (
    display_discovery_result,
    display_enumeration_results,
    display_test_results,
    save_json,
    save_csv
)
from .write_testing import test_table_write_permissions
from .signup_handler import signup_with_verification, display_user_info


console = Console()
cache = CredentialCache()


@click.group()
@click.version_option(version="0.1.0")
@click.option('--json', 'output_json', is_flag=True, help='Output results as JSON instead of formatted tables')
@click.pass_context
def cli(ctx, output_json):
    """Supabomb - Supabase Pentesting CLI Tool

    A command-line tool for discovering and testing Supabase instances
    in pentesting scenarios.
    """
    ctx.ensure_object(dict)
    ctx.obj['output_json'] = output_json


@cli.command()
@click.option('--url', '-u', help='Target webapp URL to analyze')
@click.option('--file', '-f', help='JavaScript file to analyze')
@click.option('--har', help='HAR file from network traffic')
@click.option('--output', '-o', help='Output file for results (JSON)')
@click.option('--katana', is_flag=True, help='Use Katana web crawler to discover all JS files')
@click.option('--max-js-files', default=50, help='Maximum JS files to analyze with Katana (default: 50)')
@click.option('--katana-timeout', default=120, help='Katana crawl timeout in seconds (default: 120)')
@click.option('--verbose', '-v', is_flag=True, help='Show verbose Katana output')
@click.pass_context
def discover(ctx, url, file, har, output, katana, max_js_files, katana_timeout, verbose):
    """Discover Supabase instances from web sources.

    Examples:

        supabomb discover --url https://example.com

        supabomb discover --url https://example.com --katana

        supabomb discover --file bundle.js

        supabomb discover --har network.har

        supabomb discover --url https://example.com --katana --max-js-files 100
    """
    discovery = SupabaseDiscovery()

    if url:
        if katana:
            # Use Katana for deep crawling
            console.print(f"\n[bold cyan]Crawling with Katana:[/bold cyan] {url}")
            console.print(f"[dim]Max JS files: {max_js_files}, Timeout: {katana_timeout}s[/dim]\n")

            with console.status("[bold green]Running Katana crawler..."):
                result = discovery.discover_with_katana(
                    url,
                    max_files=max_js_files,
                    timeout=katana_timeout,
                    verbose=verbose
                )
        else:
            # Standard URL analysis
            console.print(f"\n[bold cyan]Analyzing URL:[/bold cyan] {url}")
            with console.status("[bold green]Scanning for Supabase..."):
                result = discovery.discover_from_url(url)

        json_mode = ctx.obj.get('output_json', False)

        if result.found:
            if not json_mode:
                console.print("[bold green]✓[/bold green] Supabase instance found!")
            display_discovery_result(result, json_mode=json_mode)

            # Save to cache if we have credentials
            if result.credentials:
                cache.add_discovery(result.credentials, source=result.source or f"url: {url}")
                if not json_mode:
                    console.print(f"\n[dim]💾 Credentials saved to {cache.cache_file}[/dim]")

            if output:
                save_json(output, result.__dict__)
        else:
            if not json_mode:
                console.print("[bold red]✗[/bold red] No Supabase instance found")

    elif file:
        json_mode = ctx.obj.get('output_json', False)

        if not json_mode:
            console.print(f"\n[bold cyan]Analyzing file:[/bold cyan] {file}")
        result = discovery.discover_from_file(file)

        if result.found:
            if not json_mode:
                console.print("[bold green]✓[/bold green] Supabase instance found!")
            display_discovery_result(result, json_mode=json_mode)

            # Save to cache if we have credentials
            if result.credentials:
                cache.add_discovery(result.credentials, source=result.source or f"file: {file}")
                if not json_mode:
                    console.print(f"\n[dim]💾 Credentials saved to {cache.cache_file}[/dim]")

            if output:
                save_json(output, result.__dict__)
        else:
            if not json_mode:
                console.print("[bold red]✗[/bold red] No Supabase instance found")

    elif har:
        json_mode = ctx.obj.get('output_json', False)

        if not json_mode:
            console.print(f"\n[bold cyan]Analyzing HAR file:[/bold cyan] {har}")
        results = discovery.discover_from_network_traffic(har)

        if results:
            if json_mode:
                # Output all results as JSON array
                output_data = []
                for result in results:
                    output_data.append({
                        'project_ref': result.project_ref,
                        'url': result.url,
                        'anon_key': result.anon_key,
                        'source': result.source,
                        'edge_functions': [
                            {
                                'name': func.name,
                                'args': func.args,
                                'raw_args': func.raw_args,
                                'invocation_example': func.invocation_example
                            }
                            for func in (result.edge_functions or [])
                        ]
                    })
                print(json.dumps(output_data, indent=2))
            else:
                console.print(f"[bold green]✓[/bold green] Found {len(results)} Supabase instance(s)!")
                for i, result in enumerate(results, 1):
                    console.print(f"\n[bold]Instance {i}:[/bold]")
                    display_discovery_result(result, json_mode=False)

            # Save each to cache if we have credentials
            for result in results:
                if result.credentials:
                    cache.add_discovery(result.credentials, source=result.source or f"har: {har}")

            if results and results[0].credentials and not json_mode:
                console.print(f"\n[dim]💾 Credentials saved to {cache.cache_file}[/dim]")

            if output:
                save_json(output, [r.__dict__ for r in results])
        else:
            if not json_mode:
                console.print("[bold red]✗[/bold red] No Supabase instances found")

    else:
        console.print("[bold red]Error:[/bold red] Please specify --url, --file, or --har")
        raise click.Abort()


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--output', '-o', help='Output file for results (JSON)')
@click.option('--sample-size', '-s', default=5, help='Number of sample rows per table')
@click.option('--test-write', is_flag=True, help='Test INSERT/UPDATE/DELETE permissions on tables')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed email verification debugging information')
@click.pass_context
def enum(ctx, project_ref, anon_key, output, sample_size, test_write, verbose):
    """Enumerate Supabase endpoints, tables, and RPC functions.

    Examples:

        supabomb enum -p abc123xyz -k eyJ...

        supabomb enum  # Uses cached credentials

        supabomb enum -p abc123xyz -k eyJ... --sample-size 10 -o results.json

        supabomb enum --test-write  # Also test write permissions
    """
    # Load credentials from cache if not provided
    credentials = _get_credentials(project_ref, anon_key)
    if not credentials:
        console.print("[bold red]Error:[/bold red] No credentials provided and no cached credentials found.")
        console.print("Run [bold cyan]supabomb discover[/bold cyan] first or provide --project-ref and --anon-key")
        raise click.Abort()

    console.print(f"\n[bold cyan]Enumerating Supabase instance:[/bold cyan] {credentials.project_ref}")

    # Test connection
    client = SupabaseClient(credentials)
    success, error = client.test_connection()

    if not success:
        console.print(f"[bold red]✗[/bold red] Connection failed: {error}")
        raise click.Abort()

    console.print("[bold green]✓[/bold green] Connection successful")

    # Check if we have a user session for authenticated queries
    user_session = cache.get_user_session(credentials.project_ref)
    access_token = user_session.get('access_token') if user_session else None

    if access_token:
        console.print(f"[dim]🔐 Found authenticated session for {user_session['email']}[/dim]")
        # Ensure token is valid and refresh if needed
        access_token = _ensure_valid_token(client, credentials, access_token)
        if not access_token:
            console.print("[yellow]⚠[/yellow] Continuing without authentication")

    # Enumerate
    enumerator = SupabaseEnumerator(client)

    with console.status("[bold green]Enumerating resources..."):
        tables = enumerator.enumerate_tables(sample_size=sample_size)
        rpc_functions = enumerator.enumerate_rpc_functions()
        buckets = enumerator.enumerate_storage_buckets()

    # If we have a user session, also get authenticated row counts
    auth_counts = {}
    if access_token:
        with console.status("[bold green]Fetching authenticated row counts..."):
            for table in tables:
                if table.accessible:
                    auth_count = client.count_table_rows_authenticated(table.name, access_token)
                    auth_counts[table.name] = auth_count

    # Test write permissions if requested
    write_perms = {}
    if test_write:
        import uuid
        console.print(f"\n[bold cyan]Testing write permissions...[/bold cyan]")

        for table in tables:
            if verbose:
                console.print(f"[dim]Testing {table.name}...[/dim]")

            # Use sample data from table enumeration as template
            test_id = str(uuid.uuid4())
            test_data = {}

            if table.sample_data and len(table.sample_data) > 0:
                # Use the first row as template and modify it
                template = table.sample_data[0]

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
            else:
                # No sample data - try minimal insert with just ID
                columns = client.get_table_columns(table.name)
                for col in ['id', 'uuid', '_id', 'pk']:
                    if col in columns:
                        test_data[col] = test_id
                        break

            # Test INSERT
            if access_token:
                insert_success, inserted_data, insert_error = client.test_insert_authenticated(
                    table.name, access_token, test_data
                )
            else:
                insert_success, inserted_data, insert_error = client.test_insert(table.name, test_data)

            update_success = False
            delete_success = False

            if insert_success and inserted_data:
                # Extract ID for update/delete
                if isinstance(inserted_data, list) and len(inserted_data) > 0:
                    inserted_row = inserted_data[0]
                else:
                    inserted_row = inserted_data

                # Find ID field
                actual_id = None
                found_id_field = None
                for id_field in ['id', 'uuid', '_id', 'pk'] + list(inserted_row.keys()):
                    if id_field in inserted_row:
                        actual_id = inserted_row[id_field]
                        found_id_field = id_field
                        break

                if actual_id and found_id_field:
                    match_filter = {found_id_field: f'eq.{actual_id}'}

                    # Test UPDATE - modify an existing field
                    update_data = {}
                    for key, value in inserted_row.items():
                        # Find a non-ID string field to update
                        if isinstance(value, str) and key not in [found_id_field] and not any(id_pattern in key.lower() for id_pattern in ['id', 'uuid', '_id', 'pk']):
                            is_timestamp = any(pattern in key.lower() for pattern in ['created', 'updated', 'timestamp', '_at', 'date', 'time'])
                            if not is_timestamp:
                                update_data[key] = 'supabomb_updated_' + test_id[:8]
                                break

                    if not update_data:
                        for key, value in inserted_row.items():
                            if isinstance(value, (int, float)) and key not in [found_id_field]:
                                update_data[key] = value + 999
                                break

                    if update_data:
                        if access_token:
                            update_success, _ = client.test_update_authenticated(
                                table.name, access_token, match_filter, update_data
                            )
                        else:
                            update_success, _ = client.test_update(table.name, match_filter, update_data)
                    else:
                        update_success = False

                    # Test DELETE (cleanup)
                    if access_token:
                        delete_success, delete_error = client.test_delete_authenticated(
                            table.name, access_token, match_filter
                        )
                    else:
                        delete_success, delete_error = client.test_delete(table.name, match_filter)

            # Categorize insert status
            if insert_success:
                insert_status = 'allowed'
            elif insert_error:
                is_rls_block = any(x in insert_error.lower() for x in ['row-level security', 'rls', 'forbidden', 'permission denied'])
                insert_status = 'denied' if is_rls_block else 'possible'
            else:
                insert_status = 'denied'

            write_perms[table.name] = {
                'insert': insert_status,
                'update': 'allowed' if update_success else 'denied',
                'delete': 'allowed' if delete_success else 'denied'
            }

    # Display results
    json_mode = ctx.obj.get('output_json', False)
    display_enumeration_results(tables, rpc_functions, buckets,
                                 auth_counts if access_token else None,
                                 write_perms if test_write else None,
                                 json_mode=json_mode)

    # Save to file if requested
    if output:
        table_data = []
        for t in tables:
            table_info = {
                'name': t.name,
                'columns': t.columns,
                'accessible': t.accessible,
                'row_count': t.row_count,
                'sample_data': t.sample_data
            }
            # Add write permissions if tested
            if test_write and t.name in write_perms:
                table_info['write_permissions'] = write_perms[t.name]

            table_data.append(table_info)

        results = {
            'project_ref': credentials.project_ref,
            'url': credentials.url,
            'tables': table_data,
            'rpc_functions': [
                {
                    'name': f.name,
                    'parameters': f.parameters,
                    'accessible': f.accessible
                }
                for f in rpc_functions
            ],
            'storage_buckets': buckets
        }
        save_json(output, results)
        console.print(f"\n[bold green]Results saved to:[/bold green] {output}")


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--table', '-t', required=True, help='Table name to query')
@click.option('--limit', '-l', default=100, help='Maximum rows to return')
@click.option('--output', '-o', help='Output file for results (JSON or CSV)')
@click.option('--format', '-f', type=click.Choice(['json', 'csv']), default='json', help='Output format')
@click.option('--use-anon', is_flag=True, help='Force anonymous query (ignore authenticated session)')
def query(project_ref, anon_key, table, limit, output, format, use_anon):
    """Query a specific table and export data.

    By default, uses authenticated session if available, otherwise uses anonymous key.
    Use --use-anon to force anonymous query.

    Examples:

        supabomb query -t users -l 100  # Uses auth if available, else anon

        supabomb query -t users --use-anon  # Force anonymous query

        supabomb query -p abc123xyz -k eyJ... -t users -l 100

        supabomb query -t posts -o posts.json

        supabomb query -t comments -o comments.csv -f csv
    """
    # Load credentials from cache if not provided
    credentials = _get_credentials(project_ref, anon_key)
    if not credentials:
        console.print("[bold red]Error:[/bold red] No credentials provided and no cached credentials found.")
        console.print("Run [bold cyan]supabomb discover[/bold cyan] first or provide --project-ref and --anon-key")
        raise click.Abort()

    client = SupabaseClient(credentials)

    # Check for authenticated session (unless --use-anon is specified)
    access_token = None
    auth_mode = "anonymous"

    if not use_anon:
        user_session = cache.get_user_session(credentials.project_ref)
        if user_session:
            access_token = user_session.get('access_token')
            if access_token:
                # Ensure token is valid and refresh if needed
                access_token = _ensure_valid_token(client, credentials, access_token)
                if access_token:
                    auth_mode = "authenticated"
                    console.print(f"[dim]🔐 Using authenticated session: {user_session['email']}[/dim]")

    console.print(f"[bold cyan]Querying table:[/bold cyan] {table} [dim]({auth_mode})[/dim]")

    with console.status("[bold green]Fetching data..."):
        if access_token:
            success, data, error = client.query_table_authenticated(table, access_token, limit=limit)
        else:
            success, data, error = client.query_table(table, limit=limit)

    if not success:
        console.print(f"[bold red]✗[/bold red] Query failed: {error}")
        raise click.Abort()

    if not data:
        console.print("[bold yellow]No data returned[/bold yellow]")
        return

    console.print(f"[bold green]✓[/bold green] Retrieved {len(data)} rows")

    # Display sample
    if data:
        console.print("\n[bold]Sample data (first 5 rows):[/bold]")
        sample_json = json.dumps(data[:5], indent=2)
        syntax = Syntax(sample_json, "json", theme="monokai", line_numbers=True)
        console.print(syntax)

    # Save to file
    if output:
        if format == 'json':
            save_json(output, data)
        elif format == 'csv':
            save_csv(output, data)

        console.print(f"\n[bold green]Data saved to:[/bold green] {output}")


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--output', '-o', help='Output file for results (defaults to {project_ref}_dump.json)')
@click.option('--use-anon', is_flag=True, help='Force anonymous query (ignore authenticated session)')
def dump(project_ref, anon_key, output, use_anon):
    """Dump all data from all tables in the database.

    By default, uses authenticated session if available, otherwise uses anonymous key.
    Use --use-anon to force anonymous query.

    Examples:

        supabomb dump  # Uses auth if available, saves to {project_ref}_dump.json

        supabomb dump --use-anon  # Force anonymous query

        supabomb dump -o full_backup.json  # Custom output filename

        supabomb dump -p abc123xyz -k eyJ... -o backup.json
    """
    # Load credentials from cache if not provided
    credentials = _get_credentials(project_ref, anon_key)
    if not credentials:
        console.print("[bold red]Error:[/bold red] No credentials provided and no cached credentials found.")
        console.print("Run [bold cyan]supabomb discover[/bold cyan] first or provide --project-ref and --anon-key")
        raise click.Abort()

    # Determine output filename
    if not output:
        output = f"{credentials.project_ref}_dump.json"

    console.print(f"\n[bold cyan]Dumping all tables from:[/bold cyan] {credentials.project_ref}")

    client = SupabaseClient(credentials)

    # Test connection
    success, error = client.test_connection()
    if not success:
        console.print(f"[bold red]✗[/bold red] Connection failed: {error}")
        raise click.Abort()

    console.print("[bold green]✓[/bold green] Connection successful")

    # Check for authenticated session (unless --use-anon is specified)
    access_token = None
    auth_mode = "anonymous"

    if not use_anon:
        user_session = cache.get_user_session(credentials.project_ref)
        if user_session:
            access_token = user_session.get('access_token')
            if access_token:
                # Ensure token is valid and refresh if needed
                access_token = _ensure_valid_token(client, credentials, access_token)
                if access_token:
                    auth_mode = "authenticated"
                    console.print(f"[dim]🔐 Using authenticated session: {user_session['email']}[/dim]")

    console.print(f"[bold cyan]Mode:[/bold cyan] {auth_mode}\n")

    # Get all tables
    enumerator = SupabaseEnumerator(client)
    with console.status("[bold green]Discovering tables..."):
        table_names = client.list_tables()

    if not table_names:
        console.print("[bold yellow]No tables found[/bold yellow]")
        return

    console.print(f"[bold green]✓[/bold green] Found {len(table_names)} tables")

    # Query all tables
    dump_data = {
        'project_ref': credentials.project_ref,
        'url': credentials.url,
        'auth_mode': auth_mode,
        'tables': {}
    }

    successful_tables = 0
    failed_tables = 0

    for i, table_name in enumerate(table_names, 1):
        with console.status(f"[bold green]Querying table {i}/{len(table_names)}: {table_name}..."):
            if access_token:
                success, data, error = client.query_table_authenticated(table_name, access_token, limit=None)
            else:
                success, data, error = client.query_table(table_name, limit=None)

        if success:
            dump_data['tables'][table_name] = {
                'row_count': len(data) if data else 0,
                'data': data if data else []
            }
            successful_tables += 1
            console.print(f"  [green]✓[/green] {table_name}: {len(data) if data else 0} rows")
        else:
            dump_data['tables'][table_name] = {
                'error': error,
                'data': []
            }
            failed_tables += 1
            console.print(f"  [red]✗[/red] {table_name}: {error}")

    # Save to file
    console.print(f"\n[bold cyan]Saving dump to:[/bold cyan] {output}")
    save_json(output, dump_data)

    console.print(f"\n[bold green]✓ Dump complete![/bold green]")
    console.print(f"  Successful: {successful_tables} tables")
    if failed_tables > 0:
        console.print(f"  Failed: {failed_tables} tables")
    console.print(f"  Output: {output}")


@cli.command()
@click.option('--url', '-u', help='Target URL to discover Supabase credentials')
@click.option('--project-ref', '-p', help='Supabase project reference (alternative to URL)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (required with project-ref)')
@click.option('--output', '-o', required=True, help='Output file for comprehensive results (JSON)')
@click.option('--test-write', is_flag=True, help='Test INSERT/UPDATE/DELETE permissions')
@click.option('--sample-size', '-s', default=5, help='Number of sample rows per table (default: 5)')
@click.option('--katana', is_flag=True, help='Use Katana for deep discovery (if URL provided)')
@click.option('--max-js-files', default=50, help='Maximum JS files with Katana (default: 50)')
@click.option('--katana-timeout', default=120, help='Katana timeout in seconds (default: 120)')
@click.option('--verify-email', is_flag=True, help='Automatically verify email during signup')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed output')
def all(url, project_ref, anon_key, output, test_write, sample_size, katana,
        max_js_files, katana_timeout, verify_email, verbose):
    """Run complete Supabase analysis workflow.

    This command performs discovery, registration, enumeration, and data dumping in one go.
    Requires either --url for discovery or --project-ref and --anon-key for direct access.

    Examples:

        supabomb all --url https://example.com --output report.json

        supabomb all -p abc123xyz -k eyJ... --output report.json --test-write

        supabomb all --url https://example.com --katana --test-write -o full_report.json
    """
    import random
    import string
    from datetime import datetime

    console.print("\n[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]      SUPABOMB - COMPREHENSIVE ANALYSIS MODE      [/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════[/bold cyan]\n")

    # Initialize results dictionary
    results = {
        'timestamp': datetime.utcnow().isoformat(),
        'discovery': None,
        'credentials': None,
        'signup': None,
        'enumeration': None,
        'dump': None,
        'summary': {}
    }

    # ============================================================================
    # PHASE 1: DISCOVERY OR CREDENTIALS
    # ============================================================================
    console.print("[bold cyan]▶ Phase 1: Credentials Acquisition[/bold cyan]\n")

    credentials = None

    if url:
        # Discovery mode
        console.print(f"[bold cyan]Discovering from URL:[/bold cyan] {url}\n")
        discovery = SupabaseDiscovery()

        if katana:
            console.print(f"[dim]Using Katana (max files: {max_js_files}, timeout: {katana_timeout}s)[/dim]")
            with console.status("[bold green]Running Katana crawler..."):
                discovery_result = discovery.discover_with_katana(
                    url, max_files=max_js_files, timeout=katana_timeout, verbose=verbose
                )
        else:
            with console.status("[bold green]Scanning for Supabase..."):
                discovery_result = discovery.discover_from_url(url)

        if not discovery_result.found:
            console.print("[bold red]✗ No Supabase instance found[/bold red]")
            console.print("Cannot proceed without credentials")
            raise click.Abort()

        console.print("[bold green]✓ Supabase instance discovered![/bold green]")
        credentials = discovery_result.credentials

        # Save discovery results
        results['discovery'] = {
            'url': url,
            'source': discovery_result.source,
            'edge_functions': [
                {
                    'name': func.name,
                    'args': func.args,
                    'raw_args': func.raw_args,
                    'invocation_example': func.invocation_example
                }
                for func in (discovery_result.edge_functions or [])
            ]
        }

        # Display discovery info
        display_discovery_result(discovery_result)

        # Cache credentials
        cache.add_discovery(credentials, source=discovery_result.source or f"url: {url}")
        console.print(f"\n[dim]💾 Credentials cached[/dim]\n")

    elif project_ref and anon_key:
        # Direct credentials mode
        console.print("[bold cyan]Using provided credentials[/bold cyan]\n")
        credentials = SupabaseCredentials(
            project_ref=project_ref,
            anon_key=anon_key,
            url=f"https://{project_ref}.supabase.co"
        )
        console.print(f"[green]✓[/green] Project: {project_ref}")
        console.print(f"[green]✓[/green] URL: {credentials.url}\n")

    else:
        console.print("[bold red]Error:[/bold red] Must provide either --url OR (--project-ref and --anon-key)")
        raise click.Abort()

    # Store credentials in results
    results['credentials'] = {
        'project_ref': credentials.project_ref,
        'url': credentials.url,
        'anon_key': credentials.anon_key
    }

    # Test connection
    console.print("[bold cyan]Testing connection...[/bold cyan]")
    client = SupabaseClient(credentials)
    success, error = client.test_connection()

    if not success:
        console.print(f"[bold red]✗ Connection failed:[/bold red] {error}")
        raise click.Abort()

    console.print("[bold green]✓ Connection successful[/bold green]\n")

    # ============================================================================
    # PHASE 2: USER REGISTRATION
    # ============================================================================
    console.print("[bold cyan]▶ Phase 2: User Registration[/bold cyan]\n")

    # Check auth settings
    with console.status("[bold green]Checking auth settings..."):
        success, settings, error = client.get_auth_settings()

    if not success:
        console.print(f"[yellow]⚠ Could not fetch auth settings: {error}[/yellow]")
        console.print("[dim]Skipping registration phase[/dim]\n")
        results['signup'] = {'status': 'skipped', 'reason': 'auth_settings_unavailable'}
    elif settings.get('disable_signup'):
        console.print("[yellow]⚠ Signups are disabled[/yellow]")
        console.print("[dim]Skipping registration phase[/dim]\n")
        results['signup'] = {'status': 'skipped', 'reason': 'signups_disabled'}
    elif not settings.get('external', {}).get('email'):
        console.print("[yellow]⚠ Email authentication is disabled[/yellow]")
        console.print("[dim]Skipping registration phase[/dim]\n")
        results['signup'] = {'status': 'skipped', 'reason': 'email_auth_disabled'}
    else:
        # Attempt registration
        mailer_autoconfirm = settings.get('mailer_autoconfirm', False)
        temp_email_obj = None

        # Generate credentials
        random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        email = f"test_{random_id}@supabomb.local"
        password = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%', k=16))

        console.print(f"[dim]Generated email:[/dim] {email}")
        console.print(f"[dim]Generated password:[/dim] {password}")

        # Handle email verification if needed
        if not mailer_autoconfirm and verify_email:
            console.print("[dim]Email verification required - using temporary email[/dim]")
            from .email_utils import create_temp_email
            try:
                temp_email_obj = create_temp_email()
                email = temp_email_obj.address
                console.print(f"[dim]Created temporary email:[/dim] {email}")
            except Exception as e:
                console.print(f"[yellow]⚠ Could not create temp email: {e}[/yellow]")
                console.print("[dim]Continuing with generated email (may require manual verification)[/dim]")

        # Signup
        console.print(f"\n[bold cyan]Registering user...[/bold cyan]")
        with console.status("[bold green]Creating account..."):
            success, response, error = client.signup_user(email, password)

        if not success:
            console.print(f"[yellow]⚠ Signup failed: {error}[/yellow]")
            results['signup'] = {
                'status': 'failed',
                'email': email,
                'error': error
            }
        else:
            # Check if immediate access granted
            if 'access_token' in response:
                console.print("[bold green]✓ Signup successful! (No verification required)[/bold green]")

                # Save session
                cache.add_user_session(
                    project_ref=credentials.project_ref,
                    email=email,
                    password=password,
                    access_token=response['access_token'],
                    refresh_token=response['refresh_token'],
                    user_id=response['user']['id']
                )

                results['signup'] = {
                    'status': 'success',
                    'email': email,
                    'password': password,
                    'user_id': response['user']['id'],
                    'role': response['user']['role'],
                    'created_at': response['user']['created_at'],
                    'email_verified': True
                }

                console.print(f"[green]✓[/green] User ID: {response['user']['id']}")
                console.print(f"[green]✓[/green] Email: {email}")
                console.print(f"[dim]💾 Session cached for authenticated queries[/dim]\n")

            elif temp_email_obj:
                # Email verification required
                console.print("[bold cyan]⏳ Waiting for verification email...[/bold cyan]")
                from .email_utils import wait_for_verification_email

                verification_url = wait_for_verification_email(temp_email_obj, timeout=180, verbose=verbose)

                if not verification_url:
                    console.print("[yellow]⚠ No verification email received[/yellow]")
                    results['signup'] = {
                        'status': 'partial',
                        'email': email,
                        'password': password,
                        'user_id': response.get('id'),
                        'email_verified': False,
                        'reason': 'verification_timeout'
                    }
                else:
                    console.print("[bold green]✓ Email verified![/bold green]")

                    # Click verification link
                    import requests
                    try:
                        requests.get(verification_url)
                        console.print("[green]✓[/green] Verification link clicked")
                    except:
                        pass

                    # Login to get token
                    with console.status("[bold green]Logging in..."):
                        success, login_response, login_error = client.login_user(email, password)

                    if success and 'access_token' in login_response:
                        console.print("[bold green]✓ Login successful![/bold green]")

                        # Save session
                        cache.add_user_session(
                            project_ref=credentials.project_ref,
                            email=email,
                            password=password,
                            access_token=login_response['access_token'],
                            refresh_token=login_response['refresh_token'],
                            user_id=login_response['user']['id']
                        )

                        results['signup'] = {
                            'status': 'success',
                            'email': email,
                            'password': password,
                            'user_id': login_response['user']['id'],
                            'role': login_response['user']['role'],
                            'email_verified': True
                        }

                        console.print(f"[green]✓[/green] User ID: {login_response['user']['id']}")
                        console.print(f"[dim]💾 Session cached[/dim]\n")
                    else:
                        console.print(f"[yellow]⚠ Login failed: {login_error}[/yellow]")
                        results['signup'] = {
                            'status': 'partial',
                            'email': email,
                            'password': password,
                            'email_verified': True,
                            'reason': 'login_failed'
                        }
            else:
                console.print("[yellow]⚠ Email verification required but --verify-email not set[/yellow]")
                results['signup'] = {
                    'status': 'partial',
                    'email': email,
                    'password': password,
                    'user_id': response.get('id'),
                    'email_verified': False,
                    'reason': 'manual_verification_required'
                }

        console.print()

    # ============================================================================
    # PHASE 3: ENUMERATION
    # ============================================================================
    console.print("[bold cyan]▶ Phase 3: Resource Enumeration[/bold cyan]\n")

    # Check for authenticated session
    user_session = cache.get_user_session(credentials.project_ref)
    access_token = user_session.get('access_token') if user_session else None

    if access_token:
        console.print(f"[dim]🔐 Using authenticated session: {user_session['email']}[/dim]")
        access_token = _ensure_valid_token(client, credentials, access_token)
    else:
        console.print("[dim]Using anonymous access[/dim]")

    # Enumerate resources
    enumerator = SupabaseEnumerator(client)

    with console.status("[bold green]Enumerating resources..."):
        tables = enumerator.enumerate_tables(sample_size=sample_size)
        rpc_functions = enumerator.enumerate_rpc_functions()
        buckets = enumerator.enumerate_storage_buckets()

    console.print(f"[green]✓[/green] Found {len([t for t in tables if t.accessible])} accessible tables")
    console.print(f"[green]✓[/green] Found {len(rpc_functions)} RPC functions")
    console.print(f"[green]✓[/green] Found {len(buckets)} storage buckets\n")

    # Get authenticated row counts if available
    auth_counts = {}
    if access_token:
        with console.status("[bold green]Fetching authenticated row counts..."):
            for table in tables:
                if table.accessible:
                    auth_count = client.count_table_rows_authenticated(table.name, access_token)
                    auth_counts[table.name] = auth_count
        console.print(f"[green]✓[/green] Retrieved authenticated counts\n")

    # Test write permissions if requested
    write_perms = {}
    if test_write:
        console.print("[bold cyan]Testing write permissions...[/bold cyan]\n")

        import uuid
        for i, table in enumerate([t for t in tables if t.accessible], 1):
            if verbose:
                console.print(f"[dim]Testing {table.name} ({i}/{len([t for t in tables if t.accessible])})...[/dim]")

            # Generate test data
            test_id = str(uuid.uuid4())
            test_data = {}

            if table.sample_data and len(table.sample_data) > 0:
                template = table.sample_data[0]
                for key, value in template.items():
                    is_id_field = any(id_pattern in key.lower() for id_pattern in ['id', 'uuid', '_id', 'pk'])

                    if is_id_field and key in ['id', 'uuid', 'pk']:
                        test_data[key] = test_id
                    elif is_id_field:
                        test_data[key] = value
                    elif isinstance(value, str):
                        is_timestamp = any(pattern in key.lower() for pattern in ['created', 'updated', 'timestamp', '_at', 'date', 'time'])
                        if is_timestamp or (value and ('T' in value or '-' in value) and len(value) > 10):
                            test_data[key] = value
                        else:
                            test_data[key] = value[:-1] + 'X' if len(value) > 0 else 'supabomb_test'
                    elif isinstance(value, (int, float)):
                        test_data[key] = value + 1
                    elif isinstance(value, bool):
                        test_data[key] = not value
                    else:
                        test_data[key] = value

            # Test operations
            if access_token:
                insert_success, inserted_data, insert_error = client.test_insert_authenticated(
                    table.name, access_token, test_data
                )
            else:
                insert_success, inserted_data, insert_error = client.test_insert(table.name, test_data)

            update_success = False
            delete_success = False

            if insert_success and inserted_data:
                inserted_row = inserted_data[0] if isinstance(inserted_data, list) else inserted_data

                # Find ID field
                actual_id = None
                found_id_field = None
                for id_field in ['id', 'uuid', '_id', 'pk'] + list(inserted_row.keys()):
                    if id_field in inserted_row:
                        actual_id = inserted_row[id_field]
                        found_id_field = id_field
                        break

                if actual_id and found_id_field:
                    match_filter = {found_id_field: f'eq.{actual_id}'}

                    # Test UPDATE
                    update_data = {}
                    for key, value in inserted_row.items():
                        if isinstance(value, str) and key != found_id_field:
                            is_timestamp = any(pattern in key.lower() for pattern in ['created', 'updated', 'timestamp', '_at'])
                            if not is_timestamp:
                                update_data[key] = 'supabomb_updated'
                                break

                    if update_data:
                        if access_token:
                            update_success, _ = client.test_update_authenticated(
                                table.name, access_token, match_filter, update_data
                            )
                        else:
                            update_success, _ = client.test_update(table.name, match_filter, update_data)

                    # Test DELETE
                    if access_token:
                        delete_success, _ = client.test_delete_authenticated(
                            table.name, access_token, match_filter
                        )
                    else:
                        delete_success, _ = client.test_delete(table.name, match_filter)

            # Categorize results
            if insert_success:
                insert_status = 'allowed'
            elif insert_error:
                is_rls_block = any(x in insert_error.lower() for x in ['row-level security', 'rls', 'forbidden', 'permission'])
                insert_status = 'denied' if is_rls_block else 'possible'
            else:
                insert_status = 'denied'

            write_perms[table.name] = {
                'insert': insert_status,
                'update': 'allowed' if update_success else 'denied',
                'delete': 'allowed' if delete_success else 'denied'
            }

        console.print(f"[green]✓[/green] Write permission testing complete\n")

    # Display enumeration results
    display_enumeration_results(tables, rpc_functions, buckets,
                                 auth_counts if access_token else None,
                                 write_perms if test_write else None)

    # Store enumeration results
    results['enumeration'] = {
        'tables': [
            {
                'name': t.name,
                'columns': t.columns,
                'accessible': t.accessible,
                'row_count': t.row_count,
                'sample_data': t.sample_data[:2] if t.sample_data else [],  # Only store 2 samples
                'authenticated_row_count': auth_counts.get(t.name) if access_token else None,
                'write_permissions': write_perms.get(t.name) if test_write else None
            }
            for t in tables
        ],
        'rpc_functions': [
            {
                'name': f.name,
                'parameters': f.parameters,
                'accessible': f.accessible
            }
            for f in rpc_functions
        ],
        'storage_buckets': buckets
    }

    console.print()

    # ============================================================================
    # PHASE 4: DATA DUMP
    # ============================================================================
    console.print("[bold cyan]▶ Phase 4: Data Dump[/bold cyan]\n")

    table_names = [t.name for t in tables if t.accessible]

    if not table_names:
        console.print("[yellow]⚠ No accessible tables to dump[/yellow]\n")
        results['dump'] = {'status': 'skipped', 'reason': 'no_accessible_tables'}
    else:
        console.print(f"[dim]Dumping {len(table_names)} accessible tables...[/dim]\n")

        dump_data = {}
        successful_dumps = 0
        failed_dumps = 0

        for i, table_name in enumerate(table_names, 1):
            with console.status(f"[bold green]Querying {i}/{len(table_names)}: {table_name}..."):
                if access_token:
                    success, data, error = client.query_table_authenticated(table_name, access_token, limit=None)
                else:
                    success, data, error = client.query_table(table_name, limit=None)

            if success:
                dump_data[table_name] = {
                    'row_count': len(data) if data else 0,
                    'data': data if data else []
                }
                successful_dumps += 1
                console.print(f"  [green]✓[/green] {table_name}: {len(data) if data else 0} rows")
            else:
                dump_data[table_name] = {
                    'error': error,
                    'data': []
                }
                failed_dumps += 1
                console.print(f"  [yellow]⚠[/yellow] {table_name}: {error}")

        console.print(f"\n[green]✓[/green] Dump complete: {successful_dumps} successful, {failed_dumps} failed\n")

        results['dump'] = {
            'status': 'complete',
            'tables': dump_data,
            'successful_count': successful_dumps,
            'failed_count': failed_dumps
        }

    # ============================================================================
    # SUMMARY & OUTPUT
    # ============================================================================
    console.print("[bold cyan]▶ Generating Report[/bold cyan]\n")

    results['summary'] = {
        'credentials_acquired': True,
        'user_registered': results['signup']['status'] in ['success', 'partial'] if results['signup'] else False,
        'tables_discovered': len([t for t in tables if t.accessible]),
        'rpc_functions_discovered': len(rpc_functions),
        'storage_buckets_discovered': len(buckets),
        'tables_dumped': results['dump'].get('successful_count', 0) if results['dump'] else 0,
        'write_testing_performed': test_write,
    }

    # Save comprehensive report
    console.print(f"[bold cyan]Saving report to:[/bold cyan] {output}")
    save_json(output, results)

    console.print("\n[bold cyan]═══════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold green]        ANALYSIS COMPLETE - REPORT SAVED         [/bold green]")
    console.print("[bold cyan]═══════════════════════════════════════════════════[/bold cyan]\n")

    # Display summary
    summary_table = Table(show_header=False, box=box.ROUNDED, title="[bold cyan]Summary[/bold cyan]")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Project Reference", credentials.project_ref)
    summary_table.add_row("Supabase URL", credentials.url)

    if results['signup'] and results['signup']['status'] in ['success', 'partial']:
        summary_table.add_row("Test User", results['signup']['email'])
        summary_table.add_row("Test Password", results['signup']['password'])

    summary_table.add_row("Tables Discovered", str(len([t for t in tables if t.accessible])))
    summary_table.add_row("RPC Functions", str(len(rpc_functions)))
    summary_table.add_row("Storage Buckets", str(len(buckets)))

    if results['dump'] and results['dump'].get('status') == 'complete':
        summary_table.add_row("Tables Dumped", f"{results['dump']['successful_count']}/{len(table_names)}")

    if test_write:
        summary_table.add_row("Write Testing", "Performed")

    summary_table.add_row("Report File", output)

    console.print(summary_table)
    console.print()


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--edge-functions', '-e', multiple=True, help='Edge function names to test')
@click.option('--output', '-o', help='Output file for report (JSON)')
@click.pass_context
def test(ctx, project_ref, anon_key, edge_functions, output):
    """Run security tests on Supabase instance.

    Examples:

        supabomb test  # Uses cached credentials

        supabomb test -p abc123xyz -k eyJ...

        supabomb test -e function1 -e function2

        supabomb test -o report.json
    """
    # Load credentials from cache if not provided
    credentials = _get_credentials(project_ref, anon_key)
    if not credentials:
        console.print("[bold red]Error:[/bold red] No credentials provided and no cached credentials found.")
        console.print("Run [bold cyan]supabomb discover[/bold cyan] first or provide --project-ref and --anon-key")
        raise click.Abort()

    console.print(f"\n[bold cyan]Testing Supabase instance:[/bold cyan] {credentials.project_ref}")

    client = SupabaseClient(credentials)

    # Test connection
    success, error = client.test_connection()
    if not success:
        console.print(f"[bold red]✗[/bold red] Connection failed: {error}")
        raise click.Abort()

    console.print("[bold green]✓[/bold green] Connection successful\n")

    # Run tests
    tester = SupabaseTester(client)

    with console.status("[bold green]Running security tests..."):
        findings = tester.run_all_tests(edge_function_names=list(edge_functions) if edge_functions else None)

    # Generate report
    report = tester.generate_report(findings)

    # Display results
    json_mode = ctx.obj.get('output_json', False)
    display_test_results(report, json_mode=json_mode)

    # Save to file
    if output:
        save_json(output, {
            'project_ref': credentials.project_ref,
            'url': credentials.url,
            'summary': report['by_severity'],
            'risk_score': report['risk_score'],
            'findings': [
                {
                    'severity': f.severity,
                    'title': f.title,
                    'description': f.description,
                    'affected_resource': f.affected_resource,
                    'recommendation': f.recommendation,
                    'evidence': f.evidence
                }
                for f in findings
            ]
        })
        console.print(f"\n[bold green]Report saved to:[/bold green] {output}")


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--table', '-t', help='Specific table to test (optional, tests all tables if not provided)')
@click.option('--use-anon', is_flag=True, help='Force anonymous query (ignore authenticated session)')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed email verification debugging information')
@click.pass_context
def test_write(ctx, project_ref, anon_key, table, use_anon, verbose):
    """Test data manipulation (INSERT/UPDATE/DELETE) permissions on tables.

    This command will attempt to:
    1. INSERT a test row into each table
    2. UPDATE the inserted row (if insert succeeded)
    3. DELETE the row (to clean up)

    This helps identify which tables allow write operations and what level of
    data manipulation is permitted.

    By default, uses authenticated session if available, otherwise uses anonymous key.
    Use --use-anon to force anonymous testing.

    Examples:

        supabomb test-write  # Test all tables with auth if available

        supabomb test-write --use-anon  # Test all tables anonymously

        supabomb test-write -t users  # Test specific table

        supabomb test-write -p abc123xyz -k eyJ... -t posts
    """
    import uuid

    # Load credentials from cache if not provided
    credentials = _get_credentials(project_ref, anon_key)
    if not credentials:
        console.print("[bold red]Error:[/bold red] No credentials provided and no cached credentials found.")
        console.print("Run [bold cyan]supabomb discover[/bold cyan] first or provide --project-ref and --anon-key")
        raise click.Abort()

    console.print(f"\n[bold cyan]Testing write permissions:[/bold cyan] {credentials.project_ref}")

    client = SupabaseClient(credentials)

    # Test connection
    success, error = client.test_connection()
    if not success:
        console.print(f"[bold red]✗[/bold red] Connection failed: {error}")
        raise click.Abort()

    console.print("[bold green]✓[/bold green] Connection successful")

    # Check for authenticated session (unless --use-anon is specified)
    access_token = None
    auth_mode = "anonymous"

    if not use_anon:
        user_session = cache.get_user_session(credentials.project_ref)
        if user_session:
            access_token = user_session.get('access_token')
            if access_token:
                # Ensure token is valid and refresh if needed
                access_token = _ensure_valid_token(client, credentials, access_token)
                if access_token:
                    auth_mode = "authenticated"
                    console.print(f"[dim]🔐 Using authenticated session: {user_session['email']}[/dim]")

    console.print(f"[bold cyan]Mode:[/bold cyan] {auth_mode}\n")

    # Get tables to test
    if table:
        tables_to_test = [table]
    else:
        with console.status("[bold green]Discovering tables..."):
            tables_to_test = client.list_tables()

    if not tables_to_test:
        console.print("[bold yellow]No tables found[/bold yellow]")
        return

    json_mode = ctx.obj.get('output_json', False)

    if not json_mode:
        console.print(f"[bold green]✓[/bold green] Testing {len(tables_to_test)} table(s)\n")

    # Collect results
    test_results = []

    # Results table (for non-JSON mode)
    if not json_mode:
        results_table = Table(title="Write Permission Test Results", box=box.ROUNDED)
        results_table.add_column("Table", style="cyan")
        results_table.add_column("INSERT", style="yellow")
        results_table.add_column("UPDATE", style="blue")
        results_table.add_column("DELETE", style="magenta")
        results_table.add_column("Details", style="white")

    for table_name in tables_to_test:
        if verbose:
            console.print(f"[dim]Testing {table_name}...[/dim]")

        # Try to get sample data to use as template
        if access_token:
            success, sample_data, error = client.query_table_authenticated(table_name, access_token, limit=1)
        else:
            success, sample_data, error = client.query_table(table_name, limit=1)

        test_id = str(uuid.uuid4())
        test_data = {}

        if success and sample_data and len(sample_data) > 0:
            # Use the first row as template and modify it
            template = sample_data[0]

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
        else:
            # No sample data - try minimal insert with just ID
            columns = client.get_table_columns(table_name)
            for col in ['id', 'uuid', '_id', 'pk']:
                if col in columns:
                    test_data[col] = test_id
                    break

        insert_result = "✗"
        update_result = "✗"
        delete_result = "✗"
        details = ""

        # Test INSERT
        if access_token:
            insert_success, inserted_data, insert_error = client.test_insert_authenticated(
                table_name, access_token, test_data
            )
        else:
            insert_success, inserted_data, insert_error = client.test_insert(table_name, test_data)

        if insert_success:
            insert_result = "[green]✓[/green]"

            # Try to extract the actual ID from inserted data
            if inserted_data:
                if isinstance(inserted_data, list) and len(inserted_data) > 0:
                    inserted_row = inserted_data[0]
                else:
                    inserted_row = inserted_data

                # Try to find an ID field in the inserted data
                actual_id = None
                found_id_field = None
                for id_field in ['id', 'uuid', '_id', 'pk'] + list(inserted_row.keys()):
                    if id_field in inserted_row:
                        actual_id = inserted_row[id_field]
                        found_id_field = id_field
                        break

                # Test UPDATE and DELETE if we successfully inserted and found an ID
                if actual_id and found_id_field:
                    match_filter = {found_id_field: f'eq.{actual_id}'}

                    # Test UPDATE - modify an existing string field
                    update_data = {}
                    for key, value in inserted_row.items():
                        # Find a non-ID string field to update
                        if isinstance(value, str) and key not in [found_id_field] and not any(id_pattern in key.lower() for id_pattern in ['id', 'uuid', '_id', 'pk']):
                            is_timestamp = any(pattern in key.lower() for pattern in ['created', 'updated', 'timestamp', '_at', 'date', 'time'])
                            if not is_timestamp:
                                # Found a suitable field - modify it
                                update_data[key] = 'supabomb_updated_' + test_id[:8]
                                break

                    # If no string field found, try numeric
                    if not update_data:
                        for key, value in inserted_row.items():
                            if isinstance(value, (int, float)) and key not in [found_id_field]:
                                update_data[key] = value + 999
                                break

                    if update_data:
                        if access_token:
                            update_success, update_error = client.test_update_authenticated(
                                table_name, access_token, match_filter, update_data
                            )
                        else:
                            update_success, update_error = client.test_update(table_name, match_filter, update_data)
                    else:
                        update_success = False
                        update_error = "No suitable field found to test update"

                    if update_success:
                        update_result = "[green]✓[/green]"
                    else:
                        # Categorize update error
                        if update_error and any(x in update_error.lower() for x in ['row-level security', 'rls', 'forbidden']):
                            update_result = "[red]✗[/red]"
                        else:
                            update_result = "[yellow]⚠[/yellow]"

                    # Test DELETE
                    if access_token:
                        delete_success, delete_error = client.test_delete_authenticated(
                            table_name, access_token, match_filter
                        )
                    else:
                        delete_success, delete_error = client.test_delete(table_name, match_filter)

                    if delete_success:
                        delete_result = "[green]✓[/green]"
                        if update_success:
                            details = "Insert, update, and delete succeeded"
                        else:
                            details = f"Insert and delete succeeded, update failed: {update_error}"
                    else:
                        # Categorize delete error
                        if delete_error and any(x in delete_error.lower() for x in ['row-level security', 'rls', 'forbidden']):
                            delete_result = "[red]✗[/red]"
                        else:
                            delete_result = "[yellow]⚠[/yellow]"

                        if update_success:
                            details = f"Insert and update succeeded, delete failed: {delete_error}"
                        else:
                            details = f"Insert succeeded, update failed: {update_error}, delete failed: {delete_error}"
                        console.print(f"[yellow]⚠[/yellow] Could not clean up test data in {table_name}")
                else:
                    details = "Insert succeeded but no ID field found for update/delete"
                    console.print(f"[yellow]⚠[/yellow] Could not clean up test data in {table_name} (no ID field)")
            else:
                details = "Insert succeeded but no data returned"
        else:
            # Categorize insert error
            if insert_error:
                is_rls_block = any(x in insert_error.lower() for x in ['row-level security', 'rls', 'forbidden', 'permission denied'])
                is_validation_error = any(x in insert_error.lower() for x in ['violates', 'constraint', 'null value', 'foreign key', 'unique', 'check', 'invalid input syntax', 'invalid', 'type'])

                if is_rls_block:
                    # True RLS block - operation not permitted
                    insert_result = "[red]✗[/red]"
                    details = f"Insert denied by RLS: {insert_error}"
                elif is_validation_error:
                    # Schema validation error - insert might be possible with proper data
                    insert_result = "[yellow]⚠[/yellow]"
                    details = f"Insert possible but needs crafted data: {insert_error}"
                else:
                    # Other error
                    insert_result = "[red]✗[/red]"
                    details = f"Insert failed: {insert_error}"
            else:
                insert_result = "[red]✗[/red]"
                details = "Insert failed with unknown error"

            update_result = "[dim]-[/dim]"
            delete_result = "[dim]-[/dim]"

        # Collect results
        # Extract clean status (without markup) for JSON
        insert_status = "allowed" if "✓" in insert_result else ("possible" if "⚠" in insert_result else "denied")
        update_status = "allowed" if "✓" in update_result else ("possible" if "⚠" in update_result else ("not_tested" if "-" in update_result else "denied"))
        delete_status = "allowed" if "✓" in delete_result else ("possible" if "⚠" in delete_result else ("not_tested" if "-" in delete_result else "denied"))

        test_results.append({
            'table': table_name,
            'insert': insert_status,
            'update': update_status,
            'delete': delete_status,
            'details': details
        })

        if not json_mode:
            results_table.add_row(table_name, insert_result, update_result, delete_result, details)

    # Output results
    if json_mode:
        output = {
            'auth_mode': auth_mode,
            'tables_tested': len(tables_to_test),
            'results': test_results
        }
        print(json.dumps(output, indent=2))
    else:
        console.print("\n")
        console.print(results_table)
        console.print("\n[dim]Legend: ✓ = Allowed, ✗ = Denied (RLS), ⚠ = Possible with crafted data, - = Not tested[/dim]")


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--edge-functions', '-e', multiple=True, help='Edge function names to check')
@click.pass_context
def check_jwt(ctx, project_ref, anon_key, edge_functions):
    """Check which edge functions require JWT authentication.

    Examples:

        supabomb check-jwt -e function1 -e function2  # Uses cached credentials

        supabomb check-jwt -p abc123xyz -k eyJ... -e function1 -e function2
    """
    if not edge_functions:
        console.print("[bold red]Error:[/bold red] Please specify at least one edge function with -e")
        raise click.Abort()

    # Load credentials from cache if not provided
    credentials = _get_credentials(project_ref, anon_key)
    if not credentials:
        console.print("[bold red]Error:[/bold red] No credentials provided and no cached credentials found.")
        console.print("Run [bold cyan]supabomb discover[/bold cyan] first or provide --project-ref and --anon-key")
        raise click.Abort()

    console.print(f"\n[bold cyan]Checking edge functions:[/bold cyan] {credentials.project_ref}\n")

    client = SupabaseClient(credentials)
    enumerator = SupabaseEnumerator(client)

    # Test functions
    with console.status("[bold green]Testing edge functions..."):
        results = enumerator.enumerate_edge_functions(list(edge_functions))

    json_mode = ctx.obj.get('output_json', False)

    # Display results
    if json_mode:
        output = {
            'edge_functions': [
                {
                    'name': func.name,
                    'requires_jwt': func.requires_jwt,
                    'accessible_with_anon': func.accessible_with_anon,
                    'response_code': func.response_code
                }
                for func in results
            ]
        }
        print(json.dumps(output, indent=2))
    else:
        table = Table(title="Edge Function JWT Requirements", box=box.ROUNDED)
        table.add_column("Function Name", style="cyan")
        table.add_column("Requires JWT", style="yellow")
        table.add_column("Accessible with Anon Key", style="green")
        table.add_column("Status Code", style="magenta")

        for func in results:
            table.add_row(
                func.name,
                "Yes" if func.requires_jwt else "No",
                "Yes" if func.accessible_with_anon else "No",
                str(func.response_code) if func.response_code else "N/A"
            )

        console.print(table)


@cli.command()
@click.option('--clear', is_flag=True, help='Clear all cached credentials')
@click.option('--remove', '-r', help='Remove specific project by project-ref')
@click.pass_context
def cached(ctx, clear, remove):
    """List and manage cached Supabase credentials.

    Examples:

        supabomb cached  # List all cached credentials

        supabomb cached --remove abc123xyz  # Remove specific project

        supabomb cached --clear  # Clear all cached credentials
    """
    if clear:
        cache.clear()
        console.print("[bold green]✓[/bold green] All cached credentials cleared")
        return

    if remove:
        success = cache.remove(remove)
        if success:
            console.print(f"[bold green]✓[/bold green] Removed credentials for {remove}")
        else:
            console.print(f"[bold red]✗[/bold red] No cached credentials found for {remove}")
        return

    # List all cached credentials
    discoveries = cache.list_all()

    if not discoveries:
        console.print("[bold yellow]No cached credentials found[/bold yellow]")
        console.print("Run [bold cyan]supabomb discover[/bold cyan] to find Supabase instances")
        return

    json_mode = ctx.obj.get('output_json', False)

    if json_mode:
        output = {
            'cache_file': str(cache.cache_file),
            'cached_credentials': discoveries
        }
        print(json.dumps(output, indent=2))
    else:
        console.print(f"\n[bold cyan]Cached Credentials[/bold cyan] ({cache.cache_file})\n")

        table = Table(box=box.ROUNDED)
        table.add_column("#", style="dim", width=3)
        table.add_column("Project Ref", style="cyan")
        table.add_column("URL", style="blue")
        table.add_column("Source", style="yellow")
        table.add_column("Discovered", style="green")
        table.add_column("Last Used", style="magenta")

        for i, disc in enumerate(discoveries, 1):
            # Truncate timestamps for display
            discovered = disc.get("discovered_at", "")[:10]
            last_used = disc.get("last_used", "")[:10]

            # Mark the most recently used
            marker = "→" if i == 1 else ""

            table.add_row(
                f"{marker}{i}",
                disc["project_ref"],
                disc["url"],
                disc.get("source", "")[:40],
                discovered,
                last_used
            )

        console.print(table)
        console.print(f"\n[dim]The most recent (#1) will be used by default[/dim]")


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--email', '-e', help='Email for registration (random if not provided)')
@click.option('--password', help='Password for registration (random if not provided)')
@click.option('--verify-email', is_flag=True, help='Automatically verify email using temporary email service')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed email verification debugging information')
def signup(project_ref, anon_key, email, password, verify_email, verbose):
    """Register a new user account on the Supabase instance.

    This command will:
    1. Check if signup is enabled
    2. Register a new user (generates random email/password if not provided)
    3. Save credentials to cache for authenticated queries

    Examples:

        supabomb signup  # Uses cached credentials, generates random user

        supabomb signup -e test@example.com --password MyPass123

        supabomb signup -p abc123xyz -k eyJ...
    """
    import random
    import string

    # Load credentials from cache if not provided
    credentials = _get_credentials(project_ref, anon_key)
    if not credentials:
        console.print("[bold red]Error:[/bold red] No credentials provided and no cached credentials found.")
        console.print("Run [bold cyan]supabomb discover[/bold cyan] first or provide --project-ref and --anon-key")
        raise click.Abort()

    console.print(f"\n[bold cyan]Checking signup configuration:[/bold cyan] {credentials.project_ref}")

    client = SupabaseClient(credentials)

    # Get auth settings
    with console.status("[bold green]Fetching auth settings..."):
        success, settings, error = client.get_auth_settings()

    if not success:
        console.print(f"[bold red]✗[/bold red] Failed to fetch settings: {error}")
        raise click.Abort()

    # Check if signup is disabled
    if settings.get('disable_signup'):
        console.print("[bold red]✗[/bold red] Signups are disabled on this instance")
        raise click.Abort()

    # Check if email auth is enabled
    if not settings.get('external', {}).get('email'):
        console.print("[bold red]✗[/bold red] Email authentication is disabled")
        raise click.Abort()

    # Check if email verification is required
    mailer_autoconfirm = settings.get('mailer_autoconfirm', False)
    temp_email_obj = None

    if not mailer_autoconfirm:
        if verify_email:
            console.print("[bold cyan]ℹ[/bold cyan] Email verification required - using temporary email service")
            from .email_utils import create_temp_email
            try:
                temp_email_obj = create_temp_email()
                email = temp_email_obj.address
                console.print(f"[dim]Created temporary email:[/dim] {email}")
            except Exception as e:
                console.print(f"[bold red]✗[/bold red] Failed to create temporary email:")
                console.print(str(e))
                raise click.Abort()
        else:
            console.print("[bold yellow]Warning:[/bold yellow] Email verification is required")
            console.print("Signup will succeed but you won't get an access token immediately")
            console.print("Use --verify-email flag to automatically verify using temp email service")
            console.print("This tool works best with instances that have email autoconfirm enabled\n")

    # Generate random credentials if not provided
    if not email:
        random_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        email = f"test_{random_id}@supabomb.local"
        console.print(f"[dim]Generated email:[/dim] {email}")

    if not password:
        password = ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%', k=16))
        console.print(f"[dim]Generated password:[/dim] {password}")

    # Attempt signup
    console.print(f"\n[bold cyan]Registering user:[/bold cyan] {email}")
    with console.status("[bold green]Creating account..."):
        success, response, error = client.signup_user(email, password)

    if not success:
        console.print(f"[bold red]✗[/bold red] Signup failed: {error}")
        if response:
            console.print(f"[dim]Error code:[/dim] {response.get('code')}")
        raise click.Abort()

    # Check if we got immediate access
    if 'access_token' in response:
        console.print("[bold green]✓[/bold green] Signup successful! (Email verification not required)")

        # Save session to cache
        cache.add_user_session(
            project_ref=credentials.project_ref,
            email=email,
            password=password,
            access_token=response['access_token'],
            refresh_token=response['refresh_token'],
            user_id=response['user']['id']
        )

        # Display user info
        table = Table(show_header=False, box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("User ID", response['user']['id'])
        table.add_row("Email", email)
        table.add_row("Password", password)
        table.add_row("Role", response['user']['role'])
        table.add_row("Created", response['user']['created_at'])

        console.print()
        console.print(table)
        console.print(f"\n[dim]💾 Session saved to {cache.cache_file}[/dim]")
        console.print("[bold green]You can now run enum/query/test commands with authenticated access[/bold green]")

    else:
        # Email verification required
        if temp_email_obj:
            # Use temp email to verify
            console.print("[bold cyan]⏳[/bold cyan] Account created, waiting for verification email...")
            console.print(f"User ID: {response.get('id')}")

            from .email_utils import wait_for_verification_email

            if verbose:
                console.print("[dim]Checking for verification email every 3 seconds (verbose mode enabled)...[/dim]")
            else:
                console.print("[dim]Checking for verification email every 3 seconds...[/dim]")
            verification_url = wait_for_verification_email(temp_email_obj, timeout=180, verbose=verbose)

            if not verification_url:
                console.print("[bold red]✗[/bold red] Timeout: No verification email received")
                console.print("[dim]The account was created but couldn't be verified automatically[/dim]")
                raise click.Abort()

            console.print(f"[bold green]✓[/bold green] Verification email received!")
            console.print(f"[dim]Verification URL:[/dim] {verification_url}")

            # Follow the verification link (allow redirects to follow tracking URL)
            import requests
            with console.status("[bold green]Verifying email..."):
                try:
                    # Include API key in headers for Supabase verification endpoint
                    verify_response = requests.get(
                        verification_url,
                        timeout=30,
                        allow_redirects=True,
                        headers={
                            'User-Agent': 'Mozilla/5.0 (compatible; Supabomb/1.0)',
                            'apikey': credentials.anon_key
                        }
                    )
                    # Accept various success codes (200-399 are generally OK)
                    if 200 <= verify_response.status_code < 400:
                        console.print("[bold green]✓[/bold green] Email verified successfully!")
                    else:
                        console.print(f"[bold yellow]⚠[/bold yellow] Email verification may not have completed (status {verify_response.status_code})")
                        console.print("[dim]Note: Supabase uses tracking redirects which can complicate automated verification[/dim]")
                        console.print("[dim]Attempting login to check if verification succeeded...[/dim]")
                except Exception as e:
                    console.print(f"[bold yellow]⚠[/bold yellow] Verification request failed: {e}")
                    console.print("[dim]Attempting login anyway...[/dim]")

            # Now login to get access token
            console.print("\n[bold cyan]Logging in to get access token...[/bold cyan]")
            with console.status("[bold green]Authenticating..."):
                success, login_response, error = client.login_user(email, password)

            if not success:
                console.print(f"[bold red]✗[/bold red] Login failed: {error}")
                raise click.Abort()

            console.print("[bold green]✓[/bold green] Login successful!")

            # Save session to cache
            cache.add_user_session(
                project_ref=credentials.project_ref,
                email=email,
                password=password,
                access_token=login_response['access_token'],
                refresh_token=login_response['refresh_token'],
                user_id=login_response['user']['id']
            )

            # Display user info
            table = Table(show_header=False, box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("User ID", login_response['user']['id'])
            table.add_row("Email", email)
            table.add_row("Password", password)
            table.add_row("Role", login_response['user']['role'])
            table.add_row("Created", login_response['user']['created_at'])

            console.print()
            console.print(table)
            console.print(f"\n[dim]💾 Session saved to {cache.cache_file}[/dim]")
            console.print("[bold green]You can now run enum/query/test commands with authenticated access[/bold green]")

        else:
            console.print("[bold yellow]⚠[/bold yellow] Account created but email verification required")
            console.print(f"User ID: {response.get('id')}")
            console.print("Check email for confirmation link (note: test emails won't receive actual emails)")
            console.print("Use --verify-email flag to automatically verify using temp email service")
            console.print("\n[dim]This account cannot be used for authenticated queries until verified[/dim]")


def _get_credentials(project_ref: str = None, anon_key: str = None) -> Optional[SupabaseCredentials]:
    """Get credentials from arguments or cache.

    Args:
        project_ref: Optional project reference
        anon_key: Optional anon key

    Returns:
        SupabaseCredentials if found, None otherwise
    """
    # If both provided, use them directly
    if project_ref and anon_key:
        return SupabaseCredentials(
            project_ref=project_ref,
            anon_key=anon_key,
            url=f"https://{project_ref}.supabase.co"
        )

    # If only project_ref provided, try to load that specific one from cache
    if project_ref:
        credentials = cache.get_by_project_ref(project_ref)
        if credentials:
            console.print(f"[dim]📋 Using cached credentials for {project_ref}[/dim]")
            return credentials
        console.print(f"[yellow]Warning:[/yellow] No cached credentials found for {project_ref}")
        return None

    # Load latest from cache
    credentials = cache.get_latest()
    if credentials:
        console.print(f"[dim]📋 Using cached credentials for {credentials.project_ref}[/dim]")
        return credentials

    return None


def _ensure_valid_token(client: SupabaseClient, credentials: SupabaseCredentials,
                        access_token: str) -> Optional[str]:
    """Check if token is valid and refresh if needed.

    Args:
        client: SupabaseClient instance
        credentials: Supabase credentials
        access_token: Current access token

    Returns:
        Valid access token or None if refresh failed
    """
    # Check if token is expired
    if client.is_token_expired(access_token):
        console.print("[yellow]⚠[/yellow] JWT token expired, refreshing...")

        # Get user session to retrieve credentials
        user_session = cache.get_user_session(credentials.project_ref)
        if not user_session:
            console.print("[red]✗[/red] No user session found in cache, cannot refresh token")
            return None

        email = user_session.get('email')
        password = user_session.get('password')

        if not email or not password:
            console.print("[red]✗[/red] Missing email or password in session, cannot refresh token")
            return None

        # Attempt to refresh token
        success, new_token, error = client.refresh_token(email, password)
        if success and new_token:
            console.print("[green]✓[/green] Token refreshed successfully")

            # Update cache with new token
            cache.add_user_session(
                project_ref=credentials.project_ref,
                email=email,
                password=password,
                access_token=new_token,
                refresh_token=user_session.get('refresh_token', ''),
                user_id=user_session.get('user_id', '')
            )

            return new_token
        else:
            console.print(f"[red]✗[/red] Failed to refresh token: {error}")
            return None

    return access_token


if __name__ == '__main__':
    cli()
