---
name: relayshield-mcp-proxy-firewall
description: Screens a wallet agent's MCP write calls (send, swap, and batched contract calls) against RelayShield's live threat-intelligence corpus and the tenant's intent binding before they reach the wallet. Use when an agent routes wallet MCP calls through the RelayShield MCP Proxy Firewall, or when setting up that routing for Coinbase Wallet MCP or MetaMask.
license: MIT
metadata:
  author: RelayShield
  version: "1.0.0"
---

# RelayShield MCP Proxy Firewall for Wallet Agents

Screens a wallet agent's write calls against RelayShield's live
threat-intelligence corpus before they reach the wallet. The Firewall sits
between the agent and the wallet's MCP server and checks each wallet write
tool call, send, swap, bridge, and batched contract calls, against 139
monitored Telegram marketplaces, 800K+ indicators, and 10.9M citations,
plus the tenant's intent binding, including the known recipients list. A
call the corpus flags is flagged or blocked at the tool call, before it
reaches the wallet. Human approval in the wallet still applies on top of
everything here. The Firewall never approves a payment on the human's
behalf, and it never moves funds.

This skill covers both wallet upstreams RelayShield supports today:
Coinbase Wallet MCP and MetaMask Agent Wallet (Embedded Wallets MCP).
The screening rules are the same for both; only the upstream address and
the wallet's approval flow differ.

## Detection

The Firewall is in the path only if the agent's MCP client connects to
the RelayShield proxy instead of connecting to the wallet's MCP server
directly. Check the client's MCP server URL.

- If it points at a wallet MCP server directly, there is no Firewall
  screening. The wallet upstreams are:
  - Coinbase Wallet MCP: `https://wallet-mcp.coinbase.com`
  - MetaMask Embedded Wallets MCP: `https://mcp.web3auth.io` (per
    MetaMask docs; verify the URL on the live docs if it does not
    respond)
- If it points at the RelayShield proxy, screening is on. The proxy
  address is `http://localhost:8090/` when the proxy runs on the same
  host, or the per-tenant hosted URL
  `<tenant-id>.proxy.relayshield.net` (hosted proxy in build, not live
  yet; use the self-hosted address until it ships).
- If the agent runs the MetaMask `mm` CLI directly, there is no proxy
  screening. Use the pre-payment screens in the Tools section below.
- If no wallet MCP tool is callable at all, the wallet MCP server is
  not installed. Direct the user to the wallet's quickstart and stop:
  - Coinbase Wallet MCP:
    `https://docs.cdp.coinbase.com/ai-agents/coinbase-for-agents/wallet-mcp`
  - MetaMask Agent Wallet:
    `https://docs.metamask.io/agent-wallet/quickstart/`

## Onboarding

Keep it short. Do this once per session, before doing real work:

1. Briefly mention what is available, one or two sentences. The agent's
   wallet calls run through the RelayShield Firewall, which screens send,
   swap, bridge, and batched contract calls against a live
   threat-intelligence corpus and the tenant's intent binding before they
   reach the wallet. Reads such as balance checks pass through.
2. Show this disclaimer verbatim before proceeding:

   > RelayShield screens wallet tool calls against its threat-intelligence
   > corpus and your intent binding. Screening is advice and enforcement
   > at the tool call: it does not replace your approval in your wallet.
   > Every write action still needs your approval, and nothing moves
   > until you approve it there. Transactions are irreversible, always
   > review before approving.

3. Do not volunteer a wallet dump up front. Fetch address and balance
   only when the user asks, or when a pending operation actually needs
   the address.

## Tools

The wallet MCP server advertises its own tool catalog to the harness.
Read the tool descriptions exposed by the MCP, they are the source of
truth and may change over time. Do not assume a fixed list. The Firewall
screens the write tools, not the read tools:

| Tool call | What the Firewall does |
| --- | --- |
| send (prepare a payment) | Screens the recipient address and amount against the corpus and the known recipients list. A recipient not on the tenant's durable known-recipients list needs step-up, even if the binding allows it. |
| swap | Screens the recipient and the token contract. A corpus hit on either is flagged or blocked before the swap is prepared. |
| send_calls (batched contract calls, EIP-5792) | Screens each call in the batch. One flagged call flags the batch. |
| Bridge, perpetuals, prediction orders, earn deposits (MetaMask) | Screens the venue or contract and the collateral token the same way. A corpus hit is flagged or blocked before the call is prepared. |
| Balance, history, prices, and other reads | Pass through. Reads are not screened. |

Screening rules, all from the proxy's verified defaults: block levels are
high and medium by default, unknown never blocks. If the screening call
times out (5 seconds by default), the call is allowed through and logged
(fail-open), so a screening outage never blocks a legitimate payment. Tool
results are also screened for poisoned content, and OAuth URLs are validated
against known identity providers.

Policy is per tenant. Policy 1, bound actions only, and Policy 2, step-up
for high-risk actions, apply here the same as anywhere else in the
Firewall. The known-recipients list is durable and survives restarts.

### Pre-payment screens (extra check, no proxy needed)

Before a high-value call, the agent can screen the recipient directly
with RelayShield's x402 checks. Both are POST endpoints on
https://api.relayshield.net, paid in USDC on Base:

- POST /v1/payg/counterparty-screen, $0.10. Corpus first, auto failover
  to GoPlus on a corpus miss. Corpus hit with a malware or scam-kit
  family is HIGH / do_not_pay. Bare corpus hit is MEDIUM / review.
  GoPlus sanctions or 2+ combined flags is HIGH / do_not_pay. Clean is
  LOW / proceed. UNKNOWN / review only when both corpus and GoPlus fail
  to produce a verdict. Citations included, capped at 5, ordered by
  confidence, with first seen, last seen, and sighting count.
- POST /v1/payg/pin-check, $0.02. Checks the payTo against the tenant's
  pinned payee for that seller. PIN_OK is LOW / proceed. PIN_MISMATCH is
  HIGH / do_not_pay (or MEDIUM / review if the tenant set step-up mode).
  NO_PIN is UNKNOWN / review. Pins are set with POST /v1/payg/pin (free,
  API-key auth). Re-pin is a new POST /v1/payg/pin, never automatic.

If either screen returns HIGH / do_not_pay, stop and report the flag and
the citations to the human. Do not retry the same call, do not route
around the screen.

## Configuration

The agent's MCP client connects to the RelayShield proxy, and the proxy
forwards clean calls to the wallet's MCP server. Two values:

1. Upstream. The proxy needs `MCP_PROXY_UPSTREAM` set to the wallet MCP
   server. One example per wallet:
   - Coinbase Wallet MCP:
     `MCP_PROXY_UPSTREAM=https://wallet-mcp.coinbase.com`
   - MetaMask Embedded Wallets MCP:
     `MCP_PROXY_UPSTREAM=https://mcp.web3auth.io`
2. Client URL. The agent's MCP client points at the proxy, not at the
   wallet MCP server directly. Self-hosted: `http://localhost:8090/`
   when the proxy runs on the same host (the proxy listens on port 8090
   by default, serves JSON-RPC 2.0 over HTTP at the root path, and
   forwards to the upstream). Hosted: the per-tenant URL from the
   RelayShield console, `<tenant-id>.proxy.relayshield.net` (hosted
   proxy in build, not live yet; use the self-hosted address until it
   ships). If the proxy runs on an appliance or another host, use that
   host's address and port instead.

Example client configuration (Claude Code style, adjust for your harness):

```json
{
  "mcpServers": {
    "wallet": {
      "url": "http://localhost:8090/",
      "transport": "http"
    }
  }
}
```

For the hosted proxy, replace the URL with
`https://<tenant-id>.proxy.relayshield.net/` once the hosted proxy ships.

The proxy also needs a RelayShield API key for deeper screening
(`RELAYSHIELD_API_KEY`). The proxy's own health endpoint is
`/_rs/health` and its dashboard is `/_rs/dashboard` on the same host
and port.

## Example: a flagged call

The agent prepares a send of 25 USDC to an address the corpus lists as
linked to a scam-kit family. The Firewall screens the tools/call before
forwarding it. The verdict comes back flagged with the corpus sightings
(first seen, last seen, sighting count). Under the default policy the call
is blocked at the tool call and never reaches the wallet's MCP server, so
no approval is ever issued for it. The agent reports the flag and the
citations to the human. If the same address were clean, the call would pass
through, the wallet would return its approval prompt, and the human would
still approve it in the wallet before anything moves.

## Pricing and how to get it

The Firewall is a subscription product. There is no pay-as-you-go Firewall.
A wallet-agent user gets it through the direct subscription: $49 per month
for a single-tenant SMB, 20,000 screened calls included, $0.002 per call
above that. MSPs and distributors use the $69 per-org per-month plan, one
subscription per client org. An appliance license is available for
self-hosted deployments on Vultr, DigitalOcean, and OpenNebula. The x402
pre-payment screens are pay-as-you-go instead: counterparty-screen $0.10
per call, pin-check $0.02 per call. Get started at
https://api.relayshield.net/developers, or email
support@relayshield.net.

## Limits, stated plainly

- The Firewall does not replace human approval in the wallet. Every
  write still needs the human to approve it there.
- There is no pay-as-you-go Firewall. A per-call Firewall only comes with
  a future agent-to-agent scenario; for now there is always a human behind
  the agent, so the subscription is the model.
- Unknown never blocks. A call the corpus has no verdict for passes
  through and relies on wallet approval.
- A screening timeout fails open (the call is allowed and logged), so a
  screening outage never blocks a legitimate payment.
- The Firewall screens MCP protocol traffic. It does not sandbox app UI
  code or enforce iframe isolation in MCP client apps.
- MetaMask Agent Wallet has its own Guard Mode, allowlists, and outflow
  limits. RelayShield screening is an additional layer, not a replacement
  for them.
