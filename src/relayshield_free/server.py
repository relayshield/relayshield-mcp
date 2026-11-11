#!/usr/bin/env python3
"""
RelayShield Free Identity & Scam Checks — MCP Server

Exposes RelayShield's keyless, free threat-intelligence checks as callable
tools for Claude and other MCP-compatible AI agents. No API key, no signup,
no payment: every tool calls a free endpoint.

Live tools:
  check_link    — screen URL(s) for phishing/malware (POST /v1/link-check)
  check_wallet  — screen a crypto wallet before paying it (POST /v1/wallet-risk)
  check_email   — score a parsed phishing email (POST /v1/email-check, keyless)
  check_breach  — email vs 13B+ breached accounts (POST /v1/metered/breach,
                  needs RELAYSHIELD_API_KEY — a partner key)

Configuration (environment variables, all optional):
  RELAYSHIELD_API_URL — override the API base (default https://api.relayshield.net)
  RELAYSHIELD_API_KEY — partner key. Accepted by the free endpoints to lift the
                        per-IP daily allowance; required by check_breach.
                        Run keyless without it — link, wallet and email checks
                        still work on the free tier.
  RS_SOURCE_TAG       — channel label recorded by the API so per-channel usage
                        can be measured (default "mcp-free"). Distributors
                        (Claude, ChatGPT, registries) should set their own tag.

Built on MCP Python SDK 2.3.0 (mcp.server.mcpserver.MCPServer). The server
also serves the RelayShield MCP Proxy Firewall skill via the SEP-2640
Skills extension (io.modelcontextprotocol/skills): skills/list, skills/get,
and the SKILL.md file itself as a skill:// resource. The hosted proxy is
NOT the skills host for v1 (it is a hand-rolled proxy with no MCP method
dispatch); this free server is.
"""

import asyncio
import json
import os
from typing import Annotated

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import TextContent, ToolAnnotations
from pydantic import Field

from relayshield_free.skills import SKILL_URI, build_skills_extension

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

API_BASE = os.environ.get("RELAYSHIELD_API_URL", "https://api.relayshield.net").rstrip("/")
API_KEY = os.environ.get("RELAYSHIELD_API_KEY", "")
SOURCE_TAG = os.environ.get("RS_SOURCE_TAG", "mcp-free")  # recorded by the API so the channel can be measured

# ---------------------------------------------------------------------------
# Summaries (unchanged from the 1.x server: one human-readable summary per
# tool, raw upstream payloads are never returned)
# ---------------------------------------------------------------------------


def _error(text: str) -> list[TextContent]:
    return [TextContent(type="text", text=text)]


def _summarise_link(data: dict) -> str:
    """One-line-per-link human summary of a /v1/link-check response."""
    lines = []
    if "results" in data:  # batch form
        counts = data.get("counts", {})
        lines.append(
            "Checked {c} link(s): {f} flagged, {i} incomplete.".format(
                c=counts.get("checked", "?"),
                f=counts.get("flagged", "?"),
                i=counts.get("incomplete", "?"),
            )
        )
        for r in data.get("results", []):
            flag = "FLAGGED" if r.get("flagged") else r.get("level", "unknown").upper()
            reasons = "; ".join(r.get("reasons", []))
            lines.append(f"- [{flag}] {r.get('target')}" + (f" — {reasons}" if reasons else ""))
        for u in data.get("incomplete_urls", []) or []:
            lines.append(f"- [NOT CHECKED — retry] {u}")
    else:  # single-link form
        flag = "FLAGGED" if data.get("flagged") else data.get("level", "unknown").upper()
        lines.append(f"[{flag}] {data.get('target')}")
        for reason in data.get("reasons", []):
            lines.append(f"- {reason}")
        sig = data.get("signals", {})
        lines.append(
            "Signals: IOC corpus={} | threat feeds={} | domain age={}d".format(
                sig.get("ioc_corpus"), sig.get("safe_browsing"), sig.get("domain_age_days")
            )
        )
    lines.append("Note: the best verdict this check returns is 'unknown' — absence of evidence is not evidence of absence.")
    return "\n".join(lines)


def _summarise_email(data: dict) -> str:
    """Human summary of a /v1/email-check response."""
    lines = [
        "Claimed sender: {}".format(data.get("claimed_sender") or "(not parsed)"),
        "Risk: {} | Score: {}".format(data.get("risk"), data.get("score")),
    ]
    for flag in data.get("flags") or []:
        if isinstance(flag, dict):
            lines.append(f"- {flag.get('text', flag)}")
        else:
            lines.append(f"- {flag}")
    for note in data.get("notes") or []:
        lines.append(f"  note: {note}")
    auth = data.get("auth") or {}
    if auth.get("present"):
        lines.append(
            "Auth: SPF={} DKIM={} DMARC={}".format(auth.get("spf"), auth.get("dkim"), auth.get("dmarc"))
        )
    links = data.get("links") or []
    if links:
        lines.append(f"Links checked: {len(links)}")
    lines.append(
        "Note: heuristic verdict over the fields you supplied — it never answers 'safe', "
        "and a 'low' score on a vague forward is 'unknown', not 'legitimate'."
    )
    return "\n".join(lines)


def _summarise_breach(data: dict) -> str:
    """Defensive human summary of a /v1/metered/breach response."""
    breaches = data.get("breaches") or data.get("results") or []
    count = data.get("breach_count", data.get("count", len(breaches) if isinstance(breaches, list) else "?"))
    lines = [
        "Email: {}".format(data.get("email") or data.get("query") or "(unknown)"),
        "Breaches found: {}".format(count),
    ]
    if isinstance(breaches, list):
        for b in breaches[:25]:
            if isinstance(b, dict):
                name = b.get("name") or b.get("source") or b.get("title") or "?"
                date = b.get("date") or b.get("breach_date") or ""
                lines.append(f"- {name}" + (f" ({date})" if date else ""))
            else:
                lines.append(f"- {b}")
    if data.get("degraded"):
        lines.append("Warning: degraded result (incomplete upstream data) — treat as NO VERDICT, never as clean.")
    return "\n".join(lines)


def _summarise_wallet(data: dict) -> str:
    flags = data.get("risk_flags") or []
    lines = [
        "Address: {}".format(data.get("address")),
        "Chain: {} | Risk: {}".format(data.get("chain"), data.get("risk_level")),
    ]
    for f in flags:
        lines.append(f"- {f}")
    if not flags:
        lines.append("- No flags: nothing known against this address (verdict 'unknown', not 'safe').")
    return "\n".join(lines)


# Tool registry: adding a new free check is one entry here plus a summary
# function. `body` maps tool arguments to the API request body.
# `requires_key` short-circuits with setup instructions when no partner key is set.
# `open_world` feeds the ToolAnnotations openWorldHint (check_wallet reads
# live public blockchain data for an arbitrary address; the others are
# bounded corpus lookups over caller-supplied fields).
TOOLS: dict[str, dict] = {
    "check_link": {
        "path": "/v1/link-check",
        "summary": _summarise_link,
        "title": "Check links for phishing and malware",
        "open_world": False,
        "description": (
            "Checks one URL, or up to 25 URLs in a single call, against RelayShield's "
            "threat-intelligence corpus for known phishing, malware, and scam abuse. "
            "Provide either `url` (a single http:// or https:// link) or `urls` (an array "
            "of up to 25 links). Returns a per-link verdict of FLAGGED or unknown with the "
            "reasons behind each verdict, plus counts of checked, flagged, and incomplete "
            "links. A verdict of unknown means nothing is known against the link; this "
            "tool never reports a link as safe."
        ),
    },
    "check_wallet": {
        "path": "/v1/wallet-risk",
        "summary": _summarise_wallet,
        "title": "Check a crypto wallet for risk",
        "open_world": True,
        "description": (
            "Returns a read-only risk assessment of a cryptocurrency wallet address. "
            "It never moves funds or initiates transactions. Provide `address`; the chain "
            "(EVM, Solana, TON, or Bitcoin) is detected from the address format automatically. "
            "Returns a risk level of CRITICAL, HIGH, MEDIUM, LOW, or unknown, with the "
            "specific sanctions, scam, drainer, and phishing flags behind it. "
            "A verdict of unknown means nothing is known against the address; "
            "it does not mean the address is safe."
        ),
    },
    "check_email": {
        "path": "/v1/email-check",
        "summary": _summarise_email,
        "title": "Score an email for phishing signals",
        "open_world": False,
        "description": (
            "Scores a suspicious email for phishing signals from its parsed fields. "
            "Provide any of: from_address, from_name, reply_to, return_path, subject, "
            "body_text, and links (up to 25). Returns a risk level and score with the "
            "specific flags behind them; links in the email are also checked against "
            "RelayShield's threat-intelligence corpus. A verdict of unknown means nothing "
            "conclusive was found; this tool never reports an email as safe."
        ),
    },
    "check_breach": {
        "path": "/v1/metered/breach",
        "requires_key": True,
        "summary": _summarise_breach,
        "title": "Check an email against known data breaches",
        "open_world": False,
        "description": (
            "Checks whether an email address appears in known data breaches. Provide "
            "`email`. Returns the number of breaches found with the named sources behind "
            "each; a count of zero means no breaches were found in the corpus, not that "
            "the address is safe. Read-only: it only looks up breach records. Requires the "
            "RELAYSHIELD_API_KEY environment variable; without it, the tool returns setup "
            "instructions instead of calling the API."
        ),
    },
}


def _annotations(name: str) -> ToolAnnotations:
    spec = TOOLS[name]
    return ToolAnnotations(
        title=spec["title"],
        read_only_hint=True,
        destructive_hint=False,
        open_world_hint=spec["open_world"],
    )


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

INSTRUCTIONS = (
    "RelayShield free threat-intelligence checks: screen links, wallets, "
    "emails, and data breaches. No API key is needed for the link, wallet, "
    "and email checks. "
    f"Skill: the RelayShield MCP Proxy Firewall skill is served by this server "
    f"at {SKILL_URI} via the io.modelcontextprotocol/skills extension "
    "(skills/list and skills/get), and as a file at "
    "https://raw.githubusercontent.com/relayshield/relayshield-mcp/main/skills/"
    "relayshield-mcp-proxy-firewall/SKILL.md. "
    "Use it when an agent routes wallet MCP calls through the RelayShield "
    "MCP Proxy Firewall, or when setting up that routing for Coinbase "
    "Wallet MCP or MetaMask."
)

mcp = MCPServer(
    name="relayshield-free",
    instructions=INSTRUCTIONS,
    extensions=[build_skills_extension()],
)


def _upstream_proxy():
    """Egress proxy URL for the RelayShield API client, if the host sets one.

    Read from the environment explicitly instead of letting httpx read it
    (trust_env=False below). httpx 0.28.1 crashes while building its mounts
    when NO_PROXY carries bracketed IPv6 entries such as "[::1]", and a
    server-side client should only ever honour an explicit proxy setting.
    Returns None when no proxy is configured (the HF Space case: direct).
    """
    return (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
        or None
    )


async def _call_api(name: str, body: dict) -> str:
    """POST one tool's body to the RelayShield API and return the human summary.

    Upstream non-2xx raises ToolError (the wire turns it into an isError
    result carrying the JSON payload, as the 1.x server did). Every other
    failure mode returns plain text, also as the 1.x server did.
    """
    spec = TOOLS[name]
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        # Accepted by the free endpoints; lifts the per-IP daily allowance.
        headers["X-RS-API-KEY"] = API_KEY

    try:
        # trust_env=False + explicit proxy: httpx 0.28.1 crashes building
        # its mounts when NO_PROXY carries bracketed IPv6 entries such as
        # "[::1]". The proxy, when the host sets one, comes from
        # _upstream_proxy() instead, so this VM (egress proxy required) and
        # the HF Space (no proxy) both work.
        async with httpx.AsyncClient(
            timeout=28.0, trust_env=False, proxy=_upstream_proxy()
        ) as client:
            r = await client.post(API_BASE + spec["path"], json=body, headers=headers)
    except httpx.TimeoutException:
        return "Request timed out — upstream API did not respond within 28 seconds."
    except httpx.RequestError as exc:
        return f"Network error: {exc}"

    if not (200 <= r.status_code < 300):
        raise ToolError(
            json.dumps({"ok": False, "status_code": r.status_code, "body": r.text[:2000]})
        )

    try:
        payload = r.json()
    except ValueError:
        return f"Upstream returned non-JSON: {r.text[:500]}"

    if not payload.get("ok"):
        return f"Upstream error: {payload.get('error', 'unknown')}"

    text = spec["summary"](payload.get("data", {}))
    # Stdio variant (unlike the HF Space variant, which minimizes responses
    # for the OpenAI plugin review): append the raw upstream payload for
    # local debugging. It can carry request IDs, timestamps, and logging
    # metadata; never append it on the public HTTP variant.
    text += "\n\nRaw response:\n" + json.dumps(payload, indent=2)[:4000]
    return text


@mcp.tool(
    title=TOOLS["check_link"]["title"],
    description=TOOLS["check_link"]["description"],
    annotations=_annotations("check_link"),
)
async def check_link(
    url: Annotated[
        str | None,
        Field(description="A single link starting with http:// or https://. Omit when sending urls."),
    ] = None,
    urls: Annotated[
        list[str] | None,
        Field(description="Up to 25 links to check in one call. Omit when sending url."),
    ] = None,
) -> str:
    # check_link never fetches URL content or browses the web: it only looks
    # the URL up in RelayShield's bounded threat-intel corpus (IOC corpus,
    # Safe Browsing verdicts, domain registration age).
    if not url and not urls:
        return "Send either `url` (one link) or `urls` (up to 25), not neither."
    body = {k: v for k, v in {"url": url, "urls": urls}.items() if v}
    body["source"] = SOURCE_TAG
    return await _call_api("check_link", body)


@mcp.tool(
    title=TOOLS["check_wallet"]["title"],
    description=TOOLS["check_wallet"]["description"],
    annotations=_annotations("check_wallet"),
)
async def check_wallet(
    address: Annotated[
        str,
        Field(description="Wallet address to screen. Chain is auto-detected."),
    ],
) -> str:
    # check_wallet reads live public blockchain data for an arbitrary
    # user-supplied address, so it touches the open world even though the
    # tool itself is read-only.
    return await _call_api("check_wallet", {"address": address, "source": SOURCE_TAG})


@mcp.tool(
    title=TOOLS["check_email"]["title"],
    description=TOOLS["check_email"]["description"],
    annotations=_annotations("check_email"),
)
async def check_email(
    from_address: Annotated[
        str | None, Field(description="The claimed sender's address, e.g. alerts@phrase.com.")
    ] = None,
    from_name: Annotated[str | None, Field(description="The claimed sender's display name.")] = None,
    reply_to: Annotated[
        str | None,
        Field(description="Reply-To address, if present and different from from_address."),
    ] = None,
    return_path: Annotated[
        str | None, Field(description="Envelope sender, if available. Informational only.")
    ] = None,
    subject: Annotated[str | None, Field(description="Message subject.")] = None,
    body_text: Annotated[
        str | None,
        Field(description="Plain-text body, used for urgency/deadline/threat phrasing."),
    ] = None,
    links: Annotated[
        list[str] | None, Field(description="Links found in the body, up to 25.")
    ] = None,
) -> str:
    # check_email is a heuristic over caller-supplied fields plus bounded
    # corpus link checks; it never fetches remote content itself.
    body = {
        k: v
        for k, v in {
            "from_address": from_address,
            "from_name": from_name,
            "reply_to": reply_to,
            "return_path": return_path,
            "subject": subject,
            "body_text": body_text,
            "links": links,
        }.items()
        if v
    }
    body["source"] = SOURCE_TAG
    return await _call_api("check_email", body)


@mcp.tool(
    title=TOOLS["check_breach"]["title"],
    description=TOOLS["check_breach"]["description"],
    annotations=_annotations("check_breach"),
)
async def check_breach(
    email: Annotated[
        str, Field(description="Email address to check. Case-insensitive.")
    ],
) -> str:
    # check_breach is a read-only lookup against RelayShield's bounded
    # breach corpus; no open-world access.
    if not API_KEY:
        return (
            "check_breach needs a RelayShield partner API key. Set the RELAYSHIELD_API_KEY "
            "environment variable (get a key at https://api.relayshield.net/developers). "
            "The link, wallet, and email checks work keyless without one."
        )
    return await _call_api("check_breach", {"email": email, "source": SOURCE_TAG})


# ---------------------------------------------------------------------------
# Module-level wrappers: keep the 1.x call shapes (list_tools() /
# call_tool(name, arguments)) so existing callers and tests keep working.
# ---------------------------------------------------------------------------


async def list_tools() -> list:
    """List the four tools as MCP Tool objects (same shape as the 1.x server)."""
    return await mcp.list_tools()


async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Call one tool by name and return its content list (same shape as 1.x)."""
    try:
        result = await mcp.call_tool(name, arguments or {})
    except ToolError as exc:
        return _error(str(exc))
    except Exception as exc:  # unknown tool, validation failure, etc.
        return _error(str(exc))
    content = getattr(result, "content", None)
    if content is None:  # InputRequiredResult: never for these four tools
        return _error(f"Tool {name} returned an unexpected result: {result!r}")
    return list(content)


async def _main() -> None:
    await mcp.run_stdio_async()


def main_sync() -> None:
    asyncio.run(_main())


if __name__ == "__main__":
    main_sync()
