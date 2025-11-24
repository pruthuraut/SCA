# Enhanced SCA Tool - No Hardcoded Data

## Overview

The SCA (Software Composition Analysis) tool has been completely redesigned to dynamically fetch all vulnerability and security rule data from external sources instead of using hardcoded values.

## Key Features

### 1. Dynamic Vulnerability Scanning
- **OSV API Integration**: Fetches real-time vulnerability data from the Open Source Vulnerabilities database
- **NVD Fallback**: Falls back to National Vulnerability Database if OSV has no data
- **Auto-caching**: Caches results to avoid redundant API calls
- **Multi-ecosystem support**: Works with npm, pip, Maven, Docker packages

```python
# Vulnerabilities are fetched dynamically
vuln_db = VulnerabilityDatabase()
vulns = vuln_db.check_vulnerabilities('markdown-pdf', '11.0.0', 'npm')
# Result: [CVE-2023-0835] from OSV API (no hardcoded data)
```

### 2. Dynamic SAST Rules
- **RuleDatabase class**: Loads security analysis rules from JSON config files
- **Configurable patterns**: Easy to customize or add new security rules
- **Default fallback**: Uses sensible defaults if no config file is provided
- **Extensible design**: Add/remove/modify rules without code changes

```python
# Rules can be loaded from config or use defaults
analyzer = SoftwareCompositionAnalyzer(sast_config='sast_rules.json')
# Automatically loads rules from sast_rules.json or uses 7 default rules
```

## Configuration

### SAST Rules Configuration (`sast_rules.json`)

The tool now includes a `sast_rules.json` file that defines all SAST (Static Application Security Testing) rules:

```json
{
  "rules": {
    "INSECURE_PDF_GENERATION": {
      "pattern": "markdownpdf\\s*\\(\\s*\\{.*?html\\s*:\\s*true",
      "severity": "critical",
      "description": "...",
      "tags": ["rce", "input-validation"]
    },
    ...
  }
}
```

**To customize rules:**
1. Edit `sast_rules.json`
2. Add/remove/modify rules in the `rules` object
3. Change patterns, severities, or descriptions as needed
4. Run: `analyzer = SoftwareCompositionAnalyzer(sast_config='sast_rules.json')`

## Usage Examples

### Basic Usage (Default Rules)
```python
from sca_tool import SoftwareCompositionAnalyzer
from pathlib import Path

analyzer = SoftwareCompositionAnalyzer()
result = analyzer.scan_project(Path('.'), 'MyProject')
code_vulns = analyzer.sast.analyze_project(Path('.'))

# Vulnerabilities fetched from OSV/NVD APIs
# SAST rules loaded from defaults
```

### Custom SAST Rules
```python
analyzer = SoftwareCompositionAnalyzer(sast_config='custom_rules.json')
code_vulns = analyzer.sast.analyze_project(Path('.'))

# SAST rules loaded from custom_rules.json
```

### Inspect Loaded Rules
```python
rules = analyzer.sast.rule_db.get_rules()
for rule_id, rule in rules.items():
    print(f"{rule_id}: {rule.severity.value} - {rule.description}")
```

## Architecture

### VulnerabilityDatabase
- Queries OSV API for package vulnerabilities
- Falls back to NVD if OSV fails
- Caches results for performance
- No hardcoded CVEs

### RuleDatabase
- Loads rules from JSON config file (if provided)
- Falls back to DEFAULT_RULES dictionary
- All rule patterns are configurable
- Supports tags for rule categorization

### StaticAnalyzer
- Uses RuleDatabase to get analysis rules
- Scans project files against loaded rules
- Reports vulnerabilities with exact line numbers
- No hardcoded patterns

## Default SAST Rules

When no config file is provided, the tool uses 7 default rules:

1. **INSECURE_PDF_GENERATION** - markdown-pdf HTML injection
2. **UNSAFE_USER_INPUT_TO_EXEC** - Unsanitized input to exec functions
3. **DIRECT_HTML_RENDERING** - User content rendered as HTML
4. **WEAK_AUTH_CONTROL** - Weak authentication on debug endpoints
5. **HARDCODED_SECRETS** - Potential hardcoded credentials
6. **UNSAFE_EVAL** - Use of eval or dynamic code execution
7. **PATH_TRAVERSAL** - Unsanitized file system operations

## Generated Reports

The tool generates three files:

1. **sca_report.json** - Complete scan results including:
   - Dependencies with dynamic vulnerability data
   - Code vulnerabilities from SAST analysis
   - Risk scores and CVE details

2. **remediation_plan.json** - Actionable remediation steps for:
   - Each vulnerable dependency
   - Each code vulnerability
   - License issues and deprecated packages

3. **examples.py** - Usage examples and documentation

## Benefits of Dynamic Approach

✅ **Always Up-to-Date**: New CVEs detected automatically
✅ **No Maintenance**: No need to update hardcoded vulnerability lists
✅ **Extensible**: Add new SAST rules without code changes
✅ **Flexible**: Use default rules or provide custom configurations
✅ **Real-World Data**: Vulnerabilities from authoritative sources (OSV/NVD)
✅ **Performance**: Caching prevents redundant API calls
