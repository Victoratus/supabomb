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


console = Console()
cache = CredentialCache()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Supabomb - Supabase Pentesting CLI Tool

    A command-line tool for discovering and testing Supabase instances
    in pentesting scenarios.
    """
    pass


@cli.command()
@click.option('--url', '-u', help='Target webapp URL to analyze')
@click.option('--file', '-f', help='JavaScript file to analyze')
@click.option('--har', help='HAR file from network traffic')
@click.option('--output', '-o', help='Output file for results (JSON)')
def discover(url, file, har, output):
    """Discover Supabase instances from web sources.

    Examples:

        supabomb discover --url https://example.com

        supabomb discover --file bundle.js

        supabomb discover --har network.har
    """
    discovery = SupabaseDiscovery()

    if url:
        console.print(f"\n[bold cyan]Analyzing URL:[/bold cyan] {url}")
        with console.status("[bold green]Scanning for Supabase..."):
            result = discovery.discover_from_url(url)

        if result.found:
            console.print("[bold green]✓[/bold green] Supabase instance found!")
            _display_discovery_result(result)

            # Save to cache if we have credentials
            if result.credentials:
                cache.add_discovery(result.credentials, source=result.source or f"url: {url}")
                console.print(f"\n[dim]💾 Credentials saved to {cache.cache_file}[/dim]")

            if output:
                _save_json(output, result.__dict__)
        else:
            console.print("[bold red]✗[/bold red] No Supabase instance found")

    elif file:
        console.print(f"\n[bold cyan]Analyzing file:[/bold cyan] {file}")
        result = discovery.discover_from_file(file)

        if result.found:
            console.print("[bold green]✓[/bold green] Supabase instance found!")
            _display_discovery_result(result)

            # Save to cache if we have credentials
            if result.credentials:
                cache.add_discovery(result.credentials, source=result.source or f"file: {file}")
                console.print(f"\n[dim]💾 Credentials saved to {cache.cache_file}[/dim]")

            if output:
                _save_json(output, result.__dict__)
        else:
            console.print("[bold red]✗[/bold red] No Supabase instance found")

    elif har:
        console.print(f"\n[bold cyan]Analyzing HAR file:[/bold cyan] {har}")
        results = discovery.discover_from_network_traffic(har)

        if results:
            console.print(f"[bold green]✓[/bold green] Found {len(results)} Supabase instance(s)!")
            for i, result in enumerate(results, 1):
                console.print(f"\n[bold]Instance {i}:[/bold]")
                _display_discovery_result(result)

                # Save each to cache if we have credentials
                if result.credentials:
                    cache.add_discovery(result.credentials, source=result.source or f"har: {har}")

            if results and results[0].credentials:
                console.print(f"\n[dim]💾 Credentials saved to {cache.cache_file}[/dim]")

            if output:
                _save_json(output, [r.__dict__ for r in results])
        else:
            console.print("[bold red]✗[/bold red] No Supabase instances found")

    else:
        console.print("[bold red]Error:[/bold red] Please specify --url, --file, or --har")
        raise click.Abort()


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--output', '-o', help='Output file for results (JSON)')
@click.option('--sample-size', '-s', default=5, help='Number of sample rows per table')
def enum(project_ref, anon_key, output, sample_size):
    """Enumerate Supabase endpoints, tables, and RPC functions.

    Examples:

        supabomb enum -p abc123xyz -k eyJ...

        supabomb enum  # Uses cached credentials

        supabomb enum -p abc123xyz -k eyJ... --sample-size 10 -o results.json
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

    # Enumerate
    enumerator = SupabaseEnumerator(client)

    with console.status("[bold green]Enumerating resources..."):
        tables = enumerator.enumerate_tables(sample_size=sample_size)
        rpc_functions = enumerator.enumerate_rpc_functions()
        buckets = enumerator.enumerate_storage_buckets()

    # Display results
    _display_enumeration_results(tables, rpc_functions, buckets)

    # Save to file if requested
    if output:
        results = {
            'project_ref': project_ref,
            'url': url,
            'tables': [
                {
                    'name': t.name,
                    'columns': t.columns,
                    'accessible': t.accessible,
                    'row_count': t.row_count,
                    'sample_data': t.sample_data
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
        _save_json(output, results)
        console.print(f"\n[bold green]Results saved to:[/bold green] {output}")


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--table', '-t', required=True, help='Table name to query')
@click.option('--limit', '-l', default=100, help='Maximum rows to return')
@click.option('--output', '-o', help='Output file for results (JSON or CSV)')
@click.option('--format', '-f', type=click.Choice(['json', 'csv']), default='json', help='Output format')
def query(project_ref, anon_key, table, limit, output, format):
    """Query a specific table and export data.

    Examples:

        supabomb query -t users -l 100  # Uses cached credentials

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

    console.print(f"\n[bold cyan]Querying table:[/bold cyan] {table}")

    with console.status("[bold green]Fetching data..."):
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
            _save_json(output, data)
        elif format == 'csv':
            _save_csv(output, data)

        console.print(f"\n[bold green]Data saved to:[/bold green] {output}")


@cli.command()
@click.option('--project-ref', '-p', help='Supabase project reference (optional if cached)')
@click.option('--anon-key', '-k', help='Supabase anonymous API key (optional if cached)')
@click.option('--edge-functions', '-e', multiple=True, help='Edge function names to test')
@click.option('--output', '-o', help='Output file for report (JSON)')
def test(project_ref, anon_key, edge_functions, output):
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
    _display_test_results(report)

    # Save to file
    if output:
        _save_json(output, {
            'project_ref': project_ref,
            'url': url,
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
@click.option('--project-ref', '-p', required=True, help='Supabase project reference')
@click.option('--anon-key', '-k', required=True, help='Supabase anonymous API key')
@click.option('--edge-functions', '-e', multiple=True, help='Edge function names to check')
def check_jwt(project_ref, anon_key, edge_functions):
    """Check which edge functions require JWT authentication.

    Examples:

        supabomb check-jwt -p abc123xyz -k eyJ... -e function1 -e function2
    """
    if not edge_functions:
        console.print("[bold red]Error:[/bold red] Please specify at least one edge function with -e")
        raise click.Abort()

    console.print(f"\n[bold cyan]Checking edge functions:[/bold cyan] {project_ref}\n")

    # Create credentials
    url = f"https://{project_ref}.supabase.co"
    credentials = SupabaseCredentials(
        project_ref=project_ref,
        anon_key=anon_key,
        url=url
    )

    client = SupabaseClient(credentials)
    enumerator = SupabaseEnumerator(client)

    # Test functions
    with console.status("[bold green]Testing edge functions..."):
        results = enumerator.enumerate_edge_functions(list(edge_functions))

    # Display results
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


def _display_discovery_result(result):
    """Display discovery result in formatted output."""
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Project Reference", result.project_ref or "N/A")
    table.add_row("URL", result.url or "N/A")
    table.add_row("Anon Key", result.anon_key[:50] + "..." if result.anon_key else "Not found")
    table.add_row("Source", result.source or "N/A")

    console.print(table)


def _display_enumeration_results(tables, rpc_functions, buckets):
    """Display enumeration results."""
    console.print("\n[bold]Tables:[/bold]")
    table = Table(box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Accessible", style="green")
    table.add_column("Columns", style="yellow")
    table.add_column("Row Count", style="magenta")

    for t in tables:
        table.add_row(
            t.name,
            "✓" if t.accessible else "✗",
            str(len(t.columns)),
            str(t.row_count) if t.row_count is not None else "N/A"
        )

    console.print(table)

    console.print("\n[bold]RPC Functions:[/bold]")
    rpc_table = Table(box=box.ROUNDED)
    rpc_table.add_column("Name", style="cyan")
    rpc_table.add_column("Accessible", style="green")
    rpc_table.add_column("Parameters", style="yellow")

    for f in rpc_functions:
        rpc_table.add_row(
            f.name,
            "✓" if f.accessible else "✗",
            ", ".join(f.parameters) if f.parameters else "Unknown"
        )

    console.print(rpc_table)

    if buckets:
        console.print("\n[bold]Storage Buckets:[/bold]")
        bucket_table = Table(box=box.ROUNDED)
        bucket_table.add_column("Name", style="cyan")
        bucket_table.add_column("Accessible", style="green")

        for b in buckets:
            bucket_table.add_row(
                b['name'],
                "✓" if b['accessible'] else "✗"
            )

        console.print(bucket_table)


def _display_test_results(report):
    """Display test results."""
    # Summary panel
    summary_text = f"""
[bold]Total Findings:[/bold] {report['total_findings']}
[bold]Risk Score:[/bold] {report['risk_score']}

[bold red]Critical:[/bold red] {report['by_severity']['critical']}
[bold]High:[/bold] {report['by_severity']['high']}
[bold yellow]Medium:[/bold yellow] {report['by_severity']['medium']}
[bold]Low:[/bold] {report['by_severity']['low']}
[bold cyan]Info:[/bold cyan] {report['by_severity']['info']}
    """

    console.print(Panel(summary_text.strip(), title="Security Test Summary", border_style="cyan"))

    # Detailed findings
    if report['findings']:
        console.print("\n[bold]Findings:[/bold]\n")

        for i, finding in enumerate(report['findings'], 1):
            severity_color = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'white',
                'info': 'cyan'
            }.get(finding.severity, 'white')

            finding_text = f"""
[bold]Severity:[/bold] [{severity_color}]{finding.severity.upper()}[/{severity_color}]
[bold]Affected:[/bold] {finding.affected_resource}

[bold]Description:[/bold]
{finding.description}

[bold]Recommendation:[/bold]
{finding.recommendation}
            """

            console.print(Panel(
                finding_text.strip(),
                title=f"{i}. {finding.title}",
                border_style=severity_color
            ))
            console.print()


def _save_json(filename, data):
    """Save data to JSON file."""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)


def _save_csv(filename, data):
    """Save data to CSV file."""
    import csv

    if not data:
        return

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)


if __name__ == '__main__':
    cli()
