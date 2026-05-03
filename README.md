# relayshield-mcp

[RelayShield](https://relayshield.net) security intelligence as an MCP server — plug breach detection, URL/file scanning, SIM swap detection, and domain lookalike monitoring directly into Claude and any MCP-compatible AI agent.

## Tools

| Tool | What it does |
|---|---|
| `check_breach` | Email breach lookup — 13 billion+ records via HIBP |
| `scan_url` | URL malware/phishing scan across 70+ engines (async) |
| `scan_file` | Binary malware scan across 70+ AV engines (async) |
| `check_scan_result` | Poll for verdict after `scan_url` / `scan_file` |
| `check_sim_swap` | SIM swap / eSIM detection via live carrier data |
| `check_domain_lookalikes` | Typosquat and lookalike domain detection with cert transparency |

## Get an API key

Sign up at [RapidAPI — RelayShield Security Intelligence](https://rapidapi.com/relayshield/relayshield-security-intelligence).

Free tier: 100 calls/month. Paid tiers start at $29/month.

## Install

```bash
pip install relayshield-mcp
```

Or run without installing:

```bash
uvx relayshield-mcp
```

## Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "relayshield": {
      "command": "relayshield-mcp",
      "env": {
        "RELAYSHIELD_API_URL": "https://xhh3tfrhng.execute-api.us-east-1.amazonaws.com/prod",
        "RELAYSHIELD_API_KEY": "your-rapidapi-key-here"
      }
    }
  }
}
```

Quit and relaunch Claude Desktop. The hammer icon in the bottom-left will show all 6 RelayShield tools.

## Configure Claude Code (CLI)

```bash
claude mcp add relayshield \
  --command relayshield-mcp \
  --env RELAYSHIELD_API_URL=https://xhh3tfrhng.execute-api.us-east-1.amazonaws.com/prod \
  --env RELAYSHIELD_API_KEY=your-rapidapi-key-here
```

## Usage examples

Once configured, ask Claude:

```
Check whether user@example.com has been breached.
```

```
Scan this URL for malware: https://suspicious-link.example.com
```

```
Has there been a SIM swap on +14155551234?
```

```
Check acme.com for lookalike domains.
```

For URL and file scans, Claude automatically polls `check_scan_result` every 5 seconds until the verdict is ready.

## Environment variables

| Variable | Description |
|---|---|
| `RELAYSHIELD_API_URL` | API Gateway base URL (provided above) |
| `RELAYSHIELD_API_KEY` | Your RapidAPI key for RelayShield |

## Links

- [Landing page](https://relayshield.net)
- [RapidAPI listing](https://rapidapi.com/relayshield/relayshield-security-intelligence)
- [GitHub](https://github.com/relayshield/relayshield-mcp)
