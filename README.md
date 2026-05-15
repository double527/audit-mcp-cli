# audit-mcp-cli

[![npm version](https://img.shields.io/npm/v/audit-mcp-cli.svg)](https://www.npmjs.com/package/audit-mcp-cli) [![license](https://img.shields.io/npm/l/audit-mcp-cli.svg)](https://github.com/double527/audit-mcp-cli/blob/main/LICENSE) [![audit-mcp-cli MCP server](https://glama.ai/mcp/servers/double527/audit-mcp-cli/badges/score.svg)](https://glama.ai/mcp/servers/double527/audit-mcp-cli)

**English** | [中文](./README_zh.md)

A lightweight dependency vulnerability audit tool for Node.js projects. Supports CLI and MCP Server modes, covers npm and pnpm projects, and generates structured Markdown/HTML reports with full dependency chains.

## Features

- **Full dependency chains** — traces the complete path from your package.json to each vulnerable package
- **npm + pnpm support** — auto-detects package manager by lockfile
- **Remote GitHub audit** — audit any public or private repo without cloning
- **MCP Server** — integrates with AI coding assistants (Claude, Cursor, etc.)
- **Markdown / HTML reports** — clean, structured reports sorted by severity
- **CI gate** — `--fail-on` exit code for CI/CD pipelines
- **Ignore mechanism** — suppress accepted vulnerabilities with expiration dates
- **Severity filtering** — show only vulnerabilities above a threshold

## Install

```bash
# Run directly
npx audit-mcp-cli

# Or install globally
npm install -g audit-mcp-cli
```

Requires Node.js >= 18.

## Usage

```bash
# Audit current directory
audit-mcp-cli

# Specific project path
audit-mcp-cli --path /path/to/project

# Remote GitHub repo (branch)
audit-mcp-cli --remote github:facebook/react --ref main

# Remote GitHub repo (tag)
audit-mcp-cli --remote github:facebook/react --ref v18.2.0

# Remote GitHub repo (commit SHA)
audit-mcp-cli --remote github:facebook/react --ref abc123def

# HTML report
audit-mcp-cli --format html --output report.html

# CI: fail if high+ severity vulnerabilities found
audit-mcp-cli --fail-on high

# Severity filtering (only show high and critical)
audit-mcp-cli --severity high
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--path <path>` | Local project path | `process.cwd()` |
| `--remote <repo>` | Remote repo: `github:owner/repo` or `https://github.com/owner/repo` | — |
| `--ref <ref>` | Git ref (branch name / tag / commit SHA) | `main` |
| `--token <token>` | GitHub personal access token (for private repos) | `GITHUB_TOKEN` env |
| `--format <fmt>` | Report format: `md` or `html` | `md` |
| `--output <path>` | Output file path | `audit-report.md` or `.html` |
| `--severity <level>` | Minimum severity to display: `low` / `moderate` / `high` / `critical` | `low` |
| `--fail-on <level>` | CI fail threshold — exit 1 if vulnerabilities at this level or above exist | — |
| `--mcp` | Start as MCP Server | — |
| `--lang <lang>` | Language: `en` or `zh-CN` | Auto-detect from system |

### `--fail-on` exit codes

| Value | Exits 1 when |
|-------|-------------|
| `critical` | Any critical vulnerability found |
| `high` | Any high or critical found |
| `moderate` | Any moderate, high, or critical found |
| `low` | Any vulnerability found |
| *(not set)* | Always exits 0 |

## MCP Server

Run as an MCP stdio server for AI assistants:

```bash
audit-mcp-cli --mcp
```

### Claude Desktop

**Basic (local projects & public repos):**

```json
{
  "mcpServers": {
    "audit-mcp-cli": {
      "command": "npx",
      "args": ["-y", "audit-mcp-cli", "--mcp"]
    }
  }
}
```

**With GitHub token (private repos / avoid rate limits):**

```json
{
  "mcpServers": {
    "audit-mcp-cli": {
      "command": "npx",
      "args": ["-y", "audit-mcp-cli", "--mcp"],
      "env": {
        "GITHUB_TOKEN": "ghp_xxxx"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

**Basic (local projects & public repos):**

```json
{
  "mcpServers": {
    "audit-mcp-cli": {
      "command": "npx",
      "args": ["-y", "audit-mcp-cli", "--mcp"]
    }
  }
}
```

**With GitHub token (private repos / avoid rate limits):**

```json
{
  "mcpServers": {
    "audit-mcp-cli": {
      "command": "npx",
      "args": ["-y", "audit-mcp-cli", "--mcp"],
      "env": {
        "GITHUB_TOKEN": "ghp_xxxx"
      }
    }
  }
}
```

### Tool: `audit_dependencies`

The MCP server exposes one tool that supports both local and remote auditing:

| Parameter | Description |
|-----------|-------------|
| `projectPath` | Local project path |
| `remoteRepo` | Remote repo: `github:owner/repo` |
| `ref` | Git ref (branch / tag / SHA) |
| `token` | GitHub token (for private repos, or use `GITHUB_TOKEN` env) |
| `format` | `md` or `html` |
| `severity` | Minimum severity filter |
| `outputPath` | Custom output file path |

Returns: report file path + structured vulnerability details (CVSS, dependency chains, fix suggestions).

> **Token is optional.** Local project auditing never requires a token. Remote public repos work without a token (60 requests/hour). Only private repos require a GitHub token.

## Ignore Mechanism

Create `.audit-mcp-cli-ignore.json` in your project root to suppress accepted vulnerabilities:

```json
{
  "ignore": [
    {
      "packageName": "minimist",
      "advisorySource": 1179,
      "reason": "Accepted risk, limited impact in our usage",
      "expiresAt": "2025-12-31T00:00:00Z"
    }
  ]
}
```

- `packageName` — match all advisories for this package, or combine with `advisorySource` for exact match
- `expiresAt` — optional, ignore auto-expires after this date
- Ignored vulnerabilities are shown in a separate section of the report and excluded from `--fail-on` checks

## CI Integration

```yaml
# GitHub Actions example
- name: Security Audit
  run: npx audit-mcp-cli --fail-on high
```

```bash
# Generic CI
npx audit-mcp-cli --fail-on high && echo "pass" || echo "fail"
```

## License

[MIT](./LICENSE)
