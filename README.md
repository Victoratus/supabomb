# Supabomb

A powerful CLI tool for discovering and pentesting Supabase instances in authorized security assessments.

## Features

- **Automatic Credential Caching**: Discovered credentials are automatically saved
  - No need to copy/paste project refs and API keys
  - Seamlessly reuse credentials across commands
  - Manage multiple projects easily

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

### Quick Workflow

The typical workflow is simple:

```bash
# 1. Discover Supabase instance (credentials are auto-saved)
supabomb discover --url https://example.com

# 2. Use any command without providing credentials again
supabomb enum           # Enumerate resources
supabomb test           # Run security tests
supabomb query -t users # Query tables
```

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
# With explicit credentials
supabomb enum --project-ref abc123xyz --anon-key "eyJ..."

# Or use cached credentials from discovery
supabomb enum
```

### Query Tables

```bash
# Uses cached credentials
supabomb query --table users --limit 100

# Or with explicit credentials
supabomb query --project-ref abc123xyz --anon-key "eyJ..." --table users
```

### Security Testing

```bash
# Uses cached credentials
supabomb test --output report.json

# Or with explicit credentials
supabomb test --project-ref abc123xyz --anon-key "eyJ..."
```

### Check Edge Functions

```bash
# Uses cached credentials
supabomb check-jwt -e function1 -e function2

# Or with explicit credentials
supabomb check-jwt --project-ref abc123xyz --anon-key "eyJ..." -e function1
```

### Manage Cached Credentials

```bash
# List all cached credentials
supabomb cached

# Remove specific project
supabomb cached --remove abc123xyz

# Clear all cached credentials
supabomb cached --clear
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
│   ├── cache.py         # Credential caching
│   ├── models.py        # Data models
│   └── utils.py         # Utilities
├── .supabomb.json       # Cached credentials (auto-generated)
└── pyproject.toml
```

## Dependencies

- click: CLI framework
- requests: HTTP client
- beautifulsoup4: HTML parsing
- rich: Terminal formatting
- pyjwt: JWT token handling

Made for security researchers, by security researchers.
