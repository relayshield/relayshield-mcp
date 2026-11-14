# RelayShield MCP Proxy Firewall: install

## What it is

The RelayShield MCP Proxy Firewall sits between a wallet agent and its MCP servers and screens every write call (send, swap, bridge, batched contract calls) against RelayShield's live threat-intelligence corpus (139 monitored Telegram marketplaces, 800K+ indicators, 10.9M citations) and the tenant's intent binding, before the call reaches the wallet. It works with Coinbase Wallet MCP and the MetaMask Agent Wallet.

## Install the skill

Copy the skill into your agent's skills directory:

```
# Claude Code / Claude Agent SDK
cp -r skills/relayshield-mcp-proxy-firewall ~/.claude/skills/

# Or reference it directly from the repo
# https://github.com/relayshield/relayshield-mcp/tree/main/skills/relayshield-mcp-proxy-firewall
```

Read `skills/relayshield-mcp-proxy-firewall/SKILL.md` for the full instructions: detection, onboarding, tools, configuration, pricing, and limits.

## Use the hosted proxy (no install)

Every paying tenant gets a dedicated EC2 instance at `<tenant-id>.proxy.relayshield.net` with TLS and a per-tenant token. Point your agent's MCP client at that URL instead of the wallet's MCP server directly. Firewall $49/mo direct (20,000 screened calls included, $0.002 per call above that). MSP $69/mo per client org. Combined Firewall + Agent Verifiers Bundle $109/mo direct. Get started at https://api.relayshield.net/developers or email support@relayshield.net.

## Use the free MCP server (no auth)

The free RelayShield MCP server screens calls against the corpus with no auth:

```
https://relayshieldadmin-relayshield-free-mcp.hf.space/mcp
```

## Self-host

Clone the repo and follow the README for the self-hosted proxy (port 8090 by default) or the appliance license for Vultr, DigitalOcean, and OpenNebula.
