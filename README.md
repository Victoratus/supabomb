# Supabomb

A powerful CLI tool for discovering and pentesting Supabase instances in authorized security assessments.

## Features

- **Discovery**: Find Supabase instances in web applications
  - Analyze HTML pages and JavaScript bundles
  - Extract project references and API keys
  - Parse HAR files from network traffic

- **Enumeration**: Discover available resources
  - List all accessible tables and columns
  - Enumerate RPC functions
  - Discover storage buckets
  - Test edge functions

- **Security Testing**: Identify misconfigurations
  - Test Row Level Security (RLS) policies
  - Check authentication configuration
  - Validate RPC function access controls
  - Test storage bucket permissions
  - Verify edge function JWT requirements

- **Data Export**: Query and export data
  - Query tables with anonymous credentials
  - Export results in JSON or CSV format
  - Retrieve sample data for analysis

## Installation

Using uv (recommended):

```bash
cd supabomb
uv pip install -e .
# Or run directly:
uv run supabomb --help
```

## Usage

### Discover Supabase Instances

```bash
# From a web URL
supabomb discover --url https://example.com

# From a JavaScript file
supabomb discover --file bundle.js

# From HAR file
supabomb discover --har network-traffic.har
```

### Enumerate Resources

```bash
supabomb enum --project-ref abc123xyz --anon-key "eyJ..."
```

### Query Tables

```bash
supabomb query --project-ref abc123xyz --anon-key "eyJ..." --table users --limit 100
```

### Security Testing

```bash
supabomb test --project-ref abc123xyz --anon-key "eyJ..." --output report.json
```

### Check Edge Functions

```bash
supabomb check-jwt --project-ref abc123xyz --anon-key "eyJ..." -e function1 -e function2
```

## Legal & Ethical Use

**WARNING**: This tool is designed for authorized security testing only.

- Only test systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Never test systems without authorization
- Never exfiltrate sensitive personal data

Unauthorized access to computer systems is illegal.

## Architecture

```
supabomb/
├── src/supabomb/
│   ├── cli.py           # Click-based CLI
│   ├── client.py        # Supabase API client
│   ├── discovery.py     # Web discovery
│   ├── enumeration.py   # Resource enumeration
│   ├── testing.py       # Security testing
│   ├── models.py        # Data models
│   └── utils.py         # Utilities
└── pyproject.toml
```

## Dependencies

- click: CLI framework
- requests: HTTP client
- beautifulsoup4: HTML parsing
- rich: Terminal formatting
- pyjwt: JWT token handling

Made for security researchers, by security researchers.
