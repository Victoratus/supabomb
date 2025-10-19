"""Parser for extracting Supabase edge function invocations from JavaScript code."""
import re
import json
from typing import List, Dict, Any, Optional, Tuple


def extract_edge_functions(content: str) -> List[Dict[str, Any]]:
    """Extract edge function invocations from JavaScript/HTML content.

    Searches for patterns like:
    - functions.invoke("function-name", {args})
    - functions.invoke('function-name', {args})

    Args:
        content: JavaScript or HTML content to parse

    Returns:
        List of dictionaries containing function names and their arguments
    """
    edge_functions = []
    seen_functions = set()

    # Pattern to match functions.invoke calls
    # Matches: functions.invoke("name", {...}) or functions.invoke('name', {...})
    pattern = r'functions\.invoke\s*\(\s*["\']([^"\']+)["\']\s*,\s*(\{[^}]*\}(?:\s*\))?)'

    # Find all matches
    for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
        function_name = match.group(1)
        args_text = match.group(2)

        # Skip duplicates
        if function_name in seen_functions:
            continue

        seen_functions.add(function_name)

        # Try to parse the arguments
        parsed_args = parse_function_args(args_text)

        edge_functions.append({
            'name': function_name,
            'args': parsed_args,
            'raw_args': args_text.strip()
        })

    # Also look for more complex nested patterns
    # Pattern for multi-line invocations with nested objects
    complex_pattern = r'functions\.invoke\s*\(\s*["\']([^"\']+)["\']\s*,\s*(\{(?:[^{}]|\{[^{}]*\})*\})'

    for match in re.finditer(complex_pattern, content, re.MULTILINE | re.DOTALL):
        function_name = match.group(1)
        args_text = match.group(2)

        # Skip if already found
        if function_name in seen_functions:
            continue

        seen_functions.add(function_name)

        # Try to parse the arguments
        parsed_args = parse_function_args(args_text)

        edge_functions.append({
            'name': function_name,
            'args': parsed_args,
            'raw_args': args_text.strip()
        })

    return edge_functions


def parse_function_args(args_text: str) -> Optional[Dict[str, Any]]:
    """Parse JavaScript object notation to extract arguments.

    Args:
        args_text: String containing JavaScript object notation

    Returns:
        Parsed dictionary or None if parsing fails
    """
    if not args_text:
        return None

    # Clean up the text
    args_text = args_text.strip()

    # Remove trailing closing parenthesis if present
    if args_text.endswith(')'):
        args_text = args_text[:-1].strip()

    # Try to convert JavaScript object notation to JSON
    # Replace single quotes with double quotes
    json_text = args_text.replace("'", '"')

    # Fix unquoted keys (common in JavaScript)
    # Pattern: word: -> "word":
    json_text = re.sub(r'(\w+):', r'"\1":', json_text)

    try:
        # Try to parse as JSON
        return json.loads(json_text)
    except json.JSONDecodeError:
        # If JSON parsing fails, try to extract key-value pairs manually
        return extract_key_value_pairs(args_text)


def extract_key_value_pairs(text: str) -> Dict[str, Any]:
    """Extract key-value pairs from JavaScript object notation.

    Args:
        text: JavaScript object text

    Returns:
        Dictionary of extracted key-value pairs
    """
    result = {}

    # Remove outer braces
    text = text.strip()
    if text.startswith('{'):
        text = text[1:]
    if text.endswith('}'):
        text = text[:-1]

    # Simple pattern for key:value pairs
    # Matches: key:"value" or key:'value' or key:123 or key:true
    pattern = r'(\w+)\s*:\s*(["\']([^"\']+)["\']|(\d+)|(\w+))'

    for match in re.finditer(pattern, text):
        key = match.group(1)

        # Extract the value (could be string, number, or boolean)
        if match.group(3):  # Quoted string
            value = match.group(3)
        elif match.group(4):  # Number
            value = match.group(4)
            try:
                value = int(value)
            except ValueError:
                try:
                    value = float(value)
                except ValueError:
                    pass
        elif match.group(5):  # Boolean or other identifier
            value_text = match.group(5)
            if value_text == 'true':
                value = True
            elif value_text == 'false':
                value = False
            elif value_text == 'null':
                value = None
            else:
                value = value_text
        else:
            value = None

        result[key] = value

    # Also try to detect nested objects
    nested_pattern = r'(\w+)\s*:\s*\{([^}]+)\}'
    for match in re.finditer(nested_pattern, text):
        key = match.group(1)
        nested_text = match.group(2)
        result[key] = extract_key_value_pairs(nested_text)

    return result


def find_edge_function_names(content: str) -> List[str]:
    """Extract just the edge function names from content.

    Args:
        content: JavaScript or HTML content to parse

    Returns:
        List of unique function names
    """
    edge_functions = extract_edge_functions(content)
    return [func['name'] for func in edge_functions]


def format_edge_function_summary(edge_functions: List[Dict[str, Any]]) -> str:
    """Format edge functions into a readable summary.

    Args:
        edge_functions: List of edge function dictionaries

    Returns:
        Formatted string summary
    """
    if not edge_functions:
        return "No edge functions found"

    lines = [f"Found {len(edge_functions)} edge function(s):\n"]

    for i, func in enumerate(edge_functions, 1):
        lines.append(f"{i}. {func['name']}")

        if func['args']:
            # Format arguments nicely
            if isinstance(func['args'], dict):
                for key, value in func['args'].items():
                    lines.append(f"   - {key}: {value}")
            else:
                lines.append(f"   Args: {func['args']}")
        else:
            lines.append(f"   Raw: {func['raw_args'][:100]}")

        lines.append("")

    return "\n".join(lines)


def extract_edge_function_examples(content: str) -> List[Tuple[str, str]]:
    """Extract edge function names with their full invocation examples.

    Args:
        content: JavaScript or HTML content to parse

    Returns:
        List of tuples (function_name, full_invocation_example)
    """
    examples = []

    # Pattern to capture the full invocation
    pattern = r'(functions\.invoke\s*\(\s*["\']([^"\']+)["\'][^)]*\))'

    for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
        full_invocation = match.group(1)
        function_name = match.group(2)

        # Limit the example length
        if len(full_invocation) > 200:
            full_invocation = full_invocation[:200] + "..."

        examples.append((function_name, full_invocation))

    return examples
