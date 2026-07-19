# relayshield-mcp

<!-- mcp-name: io.github.nzdsf2-gif/relayshield-mcp -->

`mcp-name: io.github.nzdsf2-gif/relayshield-mcp`

[RelayShield](https://relayshield.net) security intelligence as an MCP server — plug breach detection, SIM swap detection, domain lookalike monitoring, OAuth supply chain watchlist, and URL/file scanning directly into Claude and any MCP-compatible AI agent.

## Tools

| Tool | What it does | PAYG price |
|---|---|---|
| `check_breach` | Email breach lookup — 13 billion+ records via HIBP | $0.10 USDC |
| `check_sim_swap` | SIM swap / eSIM detection via live carrier data | $0.25 USDC |
| `check_domain_lookalikes` | Typosquat and lookalike domain detection with cert transparency | $0.50 USDC |
| `check_oauth_watchlist` | OAuth-app breach + stolen-token exposure via HIBP + stealer-log corpus | $0.30 USDC |
| `check_infostealer` | Infostealer malware log lookup via Hudson Rock Cavalier | $0.15 USDC |
| `scan_wallet` | EVM wallet on-chain risk check via GoPlus Security | $0.10 USDC |
| `scan_url` | URL malware/phishing scan across 70+ engines (async) | $0.05 USDC |
| `scan_file` | Binary malware scan across 70+ AV engines (async) | $0.10 USDC |
| `check_scan_result` | Poll for verdict after `scan_url` / `scan_file` | free |
| `check_mcp_registry_risk` | Typosquat/IOC/registration-age check for MCP servers | $0.35 USDC |
| `check_prompt_injection_breach` | Breach exposure sourced from AI-agent prompt-injection attacks | $0.35 USDC |
| `check_supply_chain` | Up to 10 vendor domains checked for breach/infostealer exposure | $0.10 USDC |
| `check_session_risk` | Active/reusable stolen session (cookie/token) exposure check | $0.30 USDC |
| `check_nhi_exposure` | Non-human-identity credential exposure — API keys, service tokens, PATs | $0.40 USDC |
| `check_secret_scan` | Secrets exposed in public GitHub/GitLab repositories | $0.35 USDC |

`check_oauth_watchlist`, `check_supply_chain`, `check_session_risk`, `check_nhi_exposure`, and
`check_secret_scan` cover related ground — connected-app, session, and machine-credential exposure
for an identity or its supply chain — and are a natural set to use together when vetting an agent's
current authority, not just a login.

## Access modes

**Subscription** — API key from [RapidAPI](https://rapidapi.com/relayshield/relayshield-security-intelligence). All 15 tools available. Free tier: 100 calls/month. Paid tiers from $29/month.

**Pay-as-you-go** — No API key needed. Pay per check in USDC on Base (x402 protocol). Set `RELAYSHIELD_X_PAYMENT` with your payment proof. All 15 tools available ($0.05–$0.50/check, `check_scan_result` free). Call a tool with no payment set to receive pricing and payment instructions.

**Discovery** — Set neither key nor payment. Tool calls return payment requirements and a subscription link.

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

**Subscription (RapidAPI key):**
```json
{
  "mcpServers": {
    "relayshield": {
      "command": "relayshield-mcp",
      "env": {
        "RELAYSHIELD_API_URL": "https://atq6wtkp6k.execute-api.us-east-1.amazonaws.com/prod",
        "RELAYSHIELD_API_KEY": "your-rapidapi-key-here"
      }
    }
  }
}
```

**Pay-as-you-go (x402 USDC on Base):**
```json
{
  "mcpServers": {
    "relayshield": {
      "command": "relayshield-mcp",
      "env": {
        "RELAYSHIELD_API_URL": "https://atq6wtkp6k.execute-api.us-east-1.amazonaws.com/prod",
        "RELAYSHIELD_X_PAYMENT": "your-x402-payment-proof-here"
      }
    }
  }
}
```

Quit and relaunch Claude Desktop after editing.

## Configure Claude Code (CLI)

```bash
claude mcp add relayshield \
  --command relayshield-mcp \
  --env RELAYSHIELD_API_URL=https://atq6wtkp6k.execute-api.us-east-1.amazonaws.com/prod \
  --env RELAYSHIELD_API_KEY=your-rapidapi-key-here
```

## Usage examples

Once configured, ask Claude:

```
Check whether user@example.com has been breached.
```

```
Has there been a SIM swap on +14155551234?
```

```
Check acme.com for lookalike domains.
```

```
Are any OAuth apps connected to user@example.com in a recent breach?
```

```
Scan this URL for malware: https://suspicious-link.example.com
```

For URL and file scans, Claude automatically polls `check_scan_result` every 5 seconds until the verdict is ready.

## Environment variables

| Variable | Description |
|---|---|
| `RELAYSHIELD_API_URL` | API Gateway base URL (required) |
| `RELAYSHIELD_API_KEY` | RapidAPI subscription key (subscription mode) |
| `RELAYSHIELD_X_PAYMENT` | x402 payment proof — USDC on Base (pay-as-you-go mode) |

Set `RELAYSHIELD_API_KEY` **or** `RELAYSHIELD_X_PAYMENT` — not both. API key takes priority if both are set.

## Links

- [Landing page](https://relayshield.net)
- [RapidAPI listing](https://rapidapi.com/relayshield/relayshield-security-intelligence)
- [GitHub](https://github.com/relayshield/relayshield-mcp)
