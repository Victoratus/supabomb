"""Formatting utilities for Supabomb."""


def format_table_output(data: list, headers: list) -> str:
    """Format data as a simple table.

    Args:
        data: List of rows
        headers: Column headers

    Returns:
        Formatted table string
    """
    if not data:
        return "No data"

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in data:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    # Build table
    lines = []

    # Header
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    lines.append(header_line)
    lines.append("-" * len(header_line))

    # Data rows
    for row in data:
        line = " | ".join(str(cell).ljust(w) for cell, w in zip(row, widths))
        lines.append(line)

    return "\n".join(lines)
