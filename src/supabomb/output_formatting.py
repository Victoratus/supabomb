"""Output formatting utilities for CLI display."""
import json
import csv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box


console = Console()


def display_discovery_result(result, json_mode=False):
    """Display discovery result in formatted output.

    Args:
        result: DiscoveryResult object
        json_mode: If True, output as JSON instead of rich tables
    """
    if json_mode:
        # Build JSON output
        output = {
            'project_ref': result.project_ref,
            'url': result.url,
            'anon_key': result.anon_key,
            'source': result.source,
            'edge_functions': []
        }

        if result.edge_functions:
            for func in result.edge_functions:
                output['edge_functions'].append({
                    'name': func.name,
                    'args': func.args,
                    'raw_args': func.raw_args,
                    'invocation_example': func.invocation_example
                })

        print(json.dumps(output, indent=2))
        return

    # Original rich table output
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Project Reference", result.project_ref or "N/A")
    table.add_row("URL", result.url or "N/A")
    table.add_row("Anon Key", result.anon_key[:50] + "..." if result.anon_key else "Not found")
    table.add_row("Source", result.source or "N/A")

    # Display edge functions count
    if result.edge_functions:
        table.add_row("Edge Functions", f"{len(result.edge_functions)} discovered")

    console.print(table)

    # Display edge functions in detail if found
    if result.edge_functions:
        console.print("\n[bold]Discovered Edge Functions:[/bold]")
        edge_table = Table(box=box.ROUNDED)
        edge_table.add_column("#", style="dim", width=3)
        edge_table.add_column("Function Name", style="cyan")
        edge_table.add_column("Arguments", style="yellow")
        edge_table.add_column("Example", style="green")

        for i, func in enumerate(result.edge_functions, 1):
            # Format arguments
            if func.args:
                args_str = ", ".join(f"{k}={v}" for k, v in func.args.items())
                if len(args_str) > 40:
                    args_str = args_str[:40] + "..."
            else:
                args_str = func.raw_args[:40] + "..." if func.raw_args and len(func.raw_args) > 40 else (func.raw_args or "N/A")

            # Format example
            example_str = func.invocation_example[:60] + "..." if func.invocation_example and len(func.invocation_example) > 60 else (func.invocation_example or "N/A")

            edge_table.add_row(str(i), func.name, args_str, example_str)

        console.print(edge_table)


def display_enumeration_results(tables, rpc_functions, buckets, auth_counts=None, write_perms=None, json_mode=False):
    """Display enumeration results.

    Args:
        tables: List of table info
        rpc_functions: List of RPC functions
        buckets: List of storage buckets
        auth_counts: Optional dict of authenticated row counts per table
        write_perms: Optional dict of write permissions (insert/update/delete) per table
        json_mode: If True, output as JSON instead of rich tables
    """
    if json_mode:
        # Build JSON output
        output = {
            'tables': [],
            'rpc_functions': [],
            'storage_buckets': []
        }

        for t in tables:
            table_data = {
                'name': t.name,
                'accessible': t.accessible,
                'columns': t.columns,
                'column_count': len(t.columns),
                'anon_row_count': t.row_count
            }

            if auth_counts is not None:
                table_data['auth_row_count'] = auth_counts.get(t.name)

            if write_perms is not None and t.name in write_perms:
                table_data['write_permissions'] = write_perms[t.name]

            output['tables'].append(table_data)

        for f in rpc_functions:
            output['rpc_functions'].append({
                'name': f.name,
                'accessible': f.accessible,
                'parameters': f.parameters
            })

        for b in buckets:
            output['storage_buckets'].append({
                'name': b['name'],
                'accessible': b['accessible']
            })

        print(json.dumps(output, indent=2))
        return

    # Original rich table output
    console.print("\n[bold]Tables:[/bold]")
    table = Table(box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Read", style="green")
    table.add_column("Columns", style="yellow")
    table.add_column("Anon Rows", style="magenta")

    # Add authenticated column if we have auth data
    if auth_counts is not None:
        table.add_column("Auth Rows", style="blue")

    # Add write permission columns if tested
    if write_perms is not None:
        table.add_column("INSERT")
        table.add_column("UPDATE")
        table.add_column("DELETE")

    for t in tables:
        anon_count = str(t.row_count) if t.row_count is not None else "N/A"

        row_data = [
            t.name,
            "✓" if t.accessible else "✗",
            str(len(t.columns)),
            anon_count
        ]

        # Add authenticated count if available
        if auth_counts is not None:
            auth_count = auth_counts.get(t.name)
            auth_count_str = str(auth_count) if auth_count is not None else "N/A"
            row_data.append(auth_count_str)

        # Add write permissions if tested
        if write_perms is not None:
            perms = write_perms.get(t.name, {'insert': 'denied', 'update': 'denied', 'delete': 'denied'})

            # Helper function to get symbol for status with appropriate color
            def get_symbol(status):
                if status == 'allowed':
                    return "[green]✓[/green]"
                elif status == 'possible':
                    return "[yellow]⚠[/yellow]"
                else:  # denied
                    return "[red]✗[/red]"

            row_data.append(get_symbol(perms['insert']))
            row_data.append(get_symbol(perms['update']))
            row_data.append(get_symbol(perms['delete']))

        table.add_row(*row_data)

    console.print(table)

    # Show legend
    legend_parts = []
    if auth_counts is not None:
        legend_parts.append("Anon Rows: accessible with anonymous key | Auth Rows: accessible when authenticated")
    if write_perms is not None:
        legend_parts.append("Write permissions: ✓ = Allowed, ✗ = Denied (RLS), ⚠ = Possible with crafted data")

    if legend_parts:
        console.print(f"[dim]{' | '.join(legend_parts)}[/dim]")

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


def display_test_results(report, json_mode=False):
    """Display test results.

    Args:
        report: Test report dictionary
        json_mode: If True, output as JSON instead of rich tables
    """
    if json_mode:
        # Build JSON output
        output = {
            'total_findings': report['total_findings'],
            'risk_score': report['risk_score'],
            'by_severity': report['by_severity'],
            'findings': []
        }

        for finding in report['findings']:
            output['findings'].append({
                'severity': finding.severity,
                'title': finding.title,
                'description': finding.description,
                'affected_resource': finding.affected_resource,
                'recommendation': finding.recommendation,
                'evidence': finding.evidence
            })

        print(json.dumps(output, indent=2))
        return

    # Original rich panel output
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


def save_json(filename, data):
    """Save data to JSON file.

    Args:
        filename: Output filename
        data: Data to save
    """
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)


def save_csv(filename, data):
    """Save data to CSV file.

    Args:
        filename: Output filename
        data: List of dictionaries to save
    """
    if not data:
        return

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
