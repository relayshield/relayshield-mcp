
# relayshield-mcp

`mcp-name: io.github.nzdsf2-gif/relayshield-mcp`

[RelayShield](https://relayshield.net) security intelligence as an MCP server: plug breach detection, SIM swap detection, domain lookalike monitoring, OAuth supply chain watchlist, and URL/file scanning directly into Claude and any MCP-compatible AI agent.

RelayShield also ships a hosted proxy firewall as a remote MCP server. See [RelayShield MCP Proxy Firewall (remote server)](#relayshield-mcp-proxy-firewall-remote-server) below. It is a different product from this local package, not a duplicate of it.

## RelayShield MCP Proxy Firewall (remote server)

`mcp-name: io.github.nzdsf2-gif/relayshield-firewall` (version 0.3.0, Official MCP Registry, status active)

### Why a firewall

An MCP server runs code and tools your agent calls. A compromised, misconfigured, or shadow-installed server can poison a tool result, exfiltrate a credential, inject a prompt, or run a shell command, and the agent acts on it before anyone notices. The Firewall sits between your agent and its MCP servers and screens every tool call, every tool result, and every discovery response against RelayShield threat intelligence before the agent acts on it. It flags what it finds and, as policy dictates, blocks the call.

### What it is

The Firewall is a hosted, per-tenant proxy. Your agent connects to the Firewall as its MCP server, and the Firewall connects onward to the upstream MCP servers you use. It screens the traffic in both directions: tool lists, tool calls, and tool results. It verifies spend authorization through intent binding, and it screens payees before payment. It never calls a result safe. It reports only what is known: no flags found, flagged, blocked, or unknown.

### Endpoint

Remote endpoint: `https://tnt-demo.proxy.relayshield.net/mcp`

This is the demo tenant endpoint listed in the registry. Each tenant gets its own per-tenant endpoint of the same form: `https://<tenant-id>.proxy.relayshield.net/mcp`.

### Transport

Streamable HTTP (remote MCP). No local install, no stdio process, no package to run.

### Authentication

A per-tenant proxy token, sent as a Bearer token on every request:

```
Authorization: Bearer <your-proxy-token>
```

A token is issued per tenant when you sign up, and it is valid only for its own tenant. A request with no token, or with a token for a different tenant, is rejected (401 Unauthorized). The token is never shown in the console; keep it as a secret and do not paste it into chat or a public config.

### Tools

The Firewall exposes RelayShield threat-intelligence tools, all read-only:

| Tool | What it does | Price |
| --- | --- | --- |
| `check_link` | Screen 1–25 URLs for phishing/malware (IOC corpus, threat feeds, domain age) | free |
| `check_wallet` | Screen a crypto wallet before paying it (chain auto-detected) | free |
| `check_email` | Score a suspicious email for phishing signals; checks its links too | free |
| `check_breach` | Email vs 13B+ breached accounts | free (partner key only) |
| `counterparty-screen` | Screen a payee before payment: risk verdict and proceed/flag decision | $0.10 per check |
| `pin-check` | Verify a payment instruction (PIN) before it settles | $0.02 per check |

The Firewall also screens the upstream tools your agent calls through it. That screening is the product: it flags and, as policy dictates, blocks calls carrying poisoned content, credential exfiltration, prompt injection, or shell injection, and it blocks a settle when the intent binding behind it is revoked or expired.

### Pricing

Free first: 50 screened calls free, then the Firewall is $49/month direct. The signature bundle is the MCP Proxy Firewall plus the Agent Verifiers Bundle at $109/month (Firewall $49 and Verifiers Bundle $79 separately, $128 total, so the bundle saves $19). Included volume is 20,000 screened calls per org per month, with $0.002 per call overage. MSP pricing is $69/month per client org. See [relayshield.net](https://relayshield.net) for current terms.

### Connect

**Claude Desktop**: add to `claude_desktop_config.json`:

```
{
  "mcpServers": {
    "relayshield-firewall": {
      "url": "https://tnt-demo.proxy.relayshield.net/mcp",
      "headers": {
        "Authorization": "Bearer YOUR-PROXY-TOKEN"
      }
    }
  }
}
```

Replace `YOUR-PROXY-TOKEN` with your per-tenant proxy token, and replace the demo tenant URL with your own per-tenant endpoint (`https://<tenant-id>.proxy.relayshield.net/mcp`) once you have one. Quit and relaunch Claude Desktop after editing.

**Claude Code (CLI):**

```
claude mcp add --transport http relayshield-firewall https://tnt-demo.proxy.relayshield.net/mcp --header "Authorization: Bearer YOUR-PROXY-TOKEN"
```

## How relayshield-firewall differs from relayshield-mcp

These are two different products, not duplicate listings.

| | `relayshield-mcp` (this repo) | `relayshield-firewall` (remote server) |
| --- | --- | --- |
| Registry name | `io.github.nzdsf2-gif/relayshield-mcp` | `io.github.nzdsf2-gif/relayshield-firewall` |
| What it is | A local MCP server package (PyPI) that calls RelayShield threat-intelligence APIs | A hosted proxy firewall that sits between your agent and its MCP servers |
| Transport | stdio (runs on your machine) | Streamable HTTP (remote, nothing to install) |
| What you call | 15 threat-intelligence tools directly (breach, SIM swap, lookalikes, infostealer, scans, and more) | 4 free threat-intelligence tools, plus counterparty and PIN screens, through the proxy |
| What it enforces | Nothing. It answers your questions about a link, wallet, email, or identity | Screening and policy on every tool call, tool result, and discovery response that passes through it: flagging and, as policy dictates, blocking |
| Authorization | Your RelayShield API key, or pay-as-you-go in USDC on Base (x402) | A per-tenant proxy token (Bearer) |
| Pricing | Free tier: 100 calls/month. Paid tiers from $29/month, or pay per check ($0.05–$0.50) | 50 screened calls free, then $49/month direct, or $109/month bundled with the Agent Verifiers Bundle |
| Use it when | You want to ask RelayShield about a specific link, wallet, email, or identity from inside your agent | You want every MCP server your agent talks to screened and policed, so a poisoned tool result or a bad payee never reaches the agent |

You can use both together: point the Firewall at `relayshield-mcp` as one of its upstream servers, and the Firewall screens the threat-intelligence calls too.

## Tools

| Tool | What it does | PAYG price |
| --- | --- | --- |
| `check_breach` | Email breach lookup: 13 billion+ compromised-account records | $0.10 USDC |
| `check_sim_swap` | SIM swap / eSIM detection via live carrier data | $0.25 USDC |
| `check_domain_lookalikes` | Typosquat and lookalike domain detection with cert transparency | $0.50 USDC |
| `check_oauth_watchlist` | OAuth-app breach + stolen-token exposure from the stealer-log corpus | $0.30 USDC |
| `check_infostealer` | Infostealer malware log lookup: credentials harvested from infected devices | $0.15 USDC |
| `scan_wallet` | EVM wallet on-chain risk check | $0.10 USDC |
| `scan_url` | URL malware/phishing scan across 70+ engines (async) | $0.05 USDC |
| `scan_file` | Binary malware scan across 70+ AV engines (async) | $0.10 USDC |
| `check_scan_result` | Poll for verdict after `scan_url` / `scan_file` | free |
| `check_mcp_registry_risk` | Typosquat/IOC/registration-age check for MCP servers | $0.35 USDC |
| `check_prompt_injection_breach` | Breach exposure sourced from AI-agent prompt-injection attacks | $0.35 USDC |
| `check_supply_chain` | Up to 10 vendor domains checked for breach/infostealer exposure | $0.10 USDC |
| `check_session_risk` | Active/reusable stolen session (cookie/token) exposure check | $0.30 USDC |
| `check_nhi_exposure` | Non-human-identity credential exposure: API keys, service tokens, PATs | $0.40 USDC |
| `check_secret_scan` | Secrets exposed in public GitHub repositories | $0.35 USDC |

`check_oauth_watchlist`, `check_supply_chain`, `check_session_risk`, `check_nhi_exposure`, and `check_secret_scan` cover related ground: connected-app, session, and machine-credential exposure for an identity or its supply chain, and are a natural set to use together when vetting an agent's current authority, not just a login.

## Access modes

**Subscription**: API key from [api.relayshield.net/developers](https://api.relayshield.net/developers). All 15 tools available. Free tier: 100 calls/month. Paid tiers from $29/month.

**Pay-as-you-go**: No API key needed. Pay per check in USDC on Base (x402 protocol). Set `RELAYSHIELD_X_PAYMENT` with your payment proof. All 15 tools available ($0.05–$0.50/check, `check_scan_result` free). Call a tool with no payment set to receive pricing and payment instructions.

**Discovery**: Set neither key nor payment. Tool calls return payment requirements and a subscription link.

## Install

```
pip install relayshield-mcp
```

Or run without installing:

```
uvx relayshield-mcp
```

## Configure Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows): **Subscription (RelayShield API key):**

```
{
  "mcpServers": {
    "relayshield": {
      "command": "relayshield-mcp",
      "env": {
        "RELAYSHIELD_API_URL": "https://api.relayshield.net",
        "RELAYSHIELD_API_KEY": "your-relayshield-api-key-here"
      }
    }
  }
}
```

**Pay-as-you-go (x402 USDC on Base):**

```
{
  "mcpServers": {
    "relayshield": {
      "command": "relayshield-mcp",
      "env": {
        "RELAYSHIELD_API_URL": "https://api.relayshield.net",
        "RELAYSHIELD_X_PAYMENT": "your-x402-payment-proof-here"
      }
    }
  }
}
```

Quit and relaunch Claude Desktop after editing.

## Configure Claude Code (CLI)

```
claude mcp add relayshield \
  --command relayshield-mcp \
  --env RELAYSHIELD_API_URL=https://api.relayshield.net \
  --env RELAYSHIELD_API_KEY=<your-relayshield-api-key>
```

## Free checks server (no key, no signup)

`relayshield-free-mcp` ships in the same package and exposes RelayShield's free, keyless threat-intel checks as four MCP tools. It is the funnel into the paid server above: every summary links the deeper paid checks where they apply.

| Tool | What it does | Key needed |
| --- | --- | --- |
| `check_link` | Screen 1–25 URLs for phishing/malware (IOC corpus + threat feeds + domain age) | no |
| `check_wallet` | Screen a crypto wallet before paying it (chain auto-detected) | no |
| `check_email` | Score a suspicious email for phishing signals; checks its links too | no |
| `check_breach` | Email vs 13B+ breached accounts | partner key only |

```
pip install relayshield-mcp

# or: uvx relayshield-mcp

relayshield-free-mcp
```

**Claude Desktop**: add to `claude_desktop_config.json`:

```
{
  "mcpServers": {
    "relayshield-free": {
      "command": "relayshield-free-mcp",
      "env": {
        "RELAYSHIELD_API_URL": "https://api.relayshield.net",
        "RS_SOURCE_TAG": "mcp-free-claude"
      }
    }
  }
}
```

**ChatGPT**: ChatGPT connects to MCP servers through Developer Mode connectors, which require a remote HTTP endpoint; it does not launch a local stdio server. A hosted RelayShield MCP endpoint is live at `https://relayshieldadmin-relayshield-free-mcp.hf.space/mcp`, and the hosted Firewall remote endpoint is live at `https://tnt-demo.proxy.relayshield.net/mcp` (see [RelayShield MCP Proxy Firewall](#relayshield-mcp-proxy-firewall-remote-server) above). Set `RS_SOURCE_TAG=mcp-free-chatgpt` so usage is attributed to the ChatGPT channel. `check_breach` stays disabled until a partner key is set via `RELAYSHIELD_API_KEY`.

**Partner keys**: distributors (Claude, ChatGPT, registries) each get their own RelayShield partner key with a per-key daily call cap, set via `RELAYSHIELD_API_KEY`. Separate keys per channel mean one channel's abuse never takes down the others, and `RS_SOURCE_TAG` attributes usage per channel. The server runs fine without any key: link, wallet, and email checks stay keyless on the free tier.

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
| --- | --- |
| `RELAYSHIELD_API_URL` | API Gateway base URL (required) |
| `RELAYSHIELD_API_KEY` | RelayShield subscription key (subscription mode): get one at [api.relayshield.net/developers](https://api.relayshield.net/developers) |
| `RELAYSHIELD_X_PAYMENT` | x402 payment proof: USDC on Base (pay-as-you-go mode) |

Set `RELAYSHIELD_API_KEY` **or** `RELAYSHIELD_X_PAYMENT`, not both. API key takes priority if both are set.

## Links

- Canonical repository: [github.com/relayshield/relayshield-mcp](https://github.com/relayshield/relayshield-mcp). The repository at [github.com/nzdsf2-gif/relayshield-mcp](https://github.com/nzdsf2-gif/relayshield-mcp) is a personal fork of it.
- RelayShield MCP Proxy Firewall (remote server): registry entry `io.github.nzdsf2-gif/relayshield-firewall`, endpoint `https://tnt-demo.proxy.relayshield.net/mcp`. See the [Firewall section](#relayshield-mcp-proxy-firewall-remote-server) above.
- [Landing page](https://relayshield.net)
- [Get an API key](https://api.relayshield.net/developers)
- [GitHub](https://github.com/relayshield/relayshield-mcp)
- [Telegram bot / miniApp](https://t.me/relayshield_bot): free scam checks in chat
- [WhatsApp scam-check bot](https://wa.me/17407373961): message a link, wallet, or email
