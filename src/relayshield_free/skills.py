"""Shared Skills (SEP-2640) loading for the RelayShield free MCP server.

Canonical source: relayshield-mcp/src/relayshield_free/skills.py.
The HF Space copy (hf-space-build/skills.py) is a verbatim sync of this
file; keep the two identical and treat this file as the source of truth.

What this module does, once, at server startup:
  - locates skills/relayshield-mcp-proxy-firewall/SKILL.md,
  - parses its YAML frontmatter,
  - computes the SHA-256 digest and byte size of the raw file bytes,
  - builds the SEP-2640 skill entry (frontmatter, uri, resources manifest),
  - exposes list_skills / get_skill callables and a SEP-2133 Extension
    subclass that serves skills/list and skills/get on the MCP server.

The MCP Python SDK 2.3.0 ships the SEP-2133 extension mechanism
(mcp.server.extension.Extension) but no built-in Skills extension, so
this module implements the Skills extension on that mechanism. The wire
behaviour is the SEP-2640 shape: initialize advertises
io.modelcontextprotocol/skills in capabilities.extensions, skills/list
returns the entry, skills/get returns it for its URI and -32602 for any
other URI, and the SKILL.md bytes are served by the ordinary
resources/read method.

Security notes (SEP-2640): the frontmatter MUST NOT contain
allowed-tools (hosts must ignore it for MCP-origin skills unless the
user explicitly approves it); this module refuses to load a SKILL.md
that carries it. Digests prove the listing and the served bytes are
consistent, not that the content is trustworthy.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from mcp.server.context import ServerRequestContext
from mcp.server.extension import Extension, MethodBinding, ResourceBinding
from mcp.server.mcpserver.resources import TextResource
from mcp.shared.exceptions import MCPError
from mcp_types import INVALID_PARAMS, RequestParams

SKILL_NAME = "relayshield-mcp-proxy-firewall"
SKILL_URI = f"skill://{SKILL_NAME}/SKILL.md"
SKILLS_EXTENSION_ID = "io.modelcontextprotocol/skills"

# One file only for v1: the skill is a single SKILL.md, no supporting files.
MAX_SKILL_FILES = 512
MAX_SKILL_BYTES = 16 * 1024 * 1024


def _candidate_skill_paths() -> list[Path]:
    """Where to look for the skill file, in order.

    1. RELAYSHIELD_SKILLS_DIR, if set (tests and unusual layouts).
    2. Walk up from this file looking for skills/<name>/SKILL.md.
       Covers the installed package (src/relayshield_free/skills.py with
       skills/ at the repo root) and the HF Space copy (/app/skills.py
       with skills/ at /app).
    3. ./skills/<name>/SKILL.md relative to the working directory.
    """
    candidates: list[Path] = []
    env_dir = os.environ.get("RELAYSHIELD_SKILLS_DIR")
    if env_dir:
        candidates.append(Path(env_dir) / SKILL_NAME / "SKILL.md")
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidates.append(parent / "skills" / SKILL_NAME / "SKILL.md")
    candidates.append(Path.cwd() / "skills" / SKILL_NAME / "SKILL.md")
    return candidates


def find_skill_file() -> Path:
    """Return the first existing SKILL.md candidate, or raise FileNotFoundError."""
    for candidate in _candidate_skill_paths():
        if candidate.is_file():
            return candidate
    searched = "\n".join(f"  - {p}" for p in _candidate_skill_paths())
    raise FileNotFoundError(
        f"Could not find skills/{SKILL_NAME}/SKILL.md. Searched:\n{searched}"
    )


@dataclass
class Skill:
    """One loaded skill: frontmatter, content, digest, and its SEP-2640 entry."""

    name: str
    uri: str
    frontmatter: dict[str, Any]
    text: str
    raw: bytes
    digest: str  # "sha256:<64 lowercase hex>" of the raw file bytes
    size: int  # byte length of the raw file bytes

    @property
    def entry(self) -> dict[str, Any]:
        """SEP-2640 skill entry: frontmatter (verbatim), uri, resources manifest."""
        return {
            "frontmatter": self.frontmatter,
            "uri": self.uri,
            "resources": [
                {"uri": self.uri, "digest": self.digest, "size": self.size}
            ],
        }


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Split a SKILL.md into (frontmatter dict, body). Raises ValueError."""
    if not text.startswith("---\n") and not text.startswith("---\r\n"):
        raise ValueError("SKILL.md must begin with YAML frontmatter delimited by ---")
    # Find the closing --- on its own line.
    lines = text.splitlines(keepends=True)
    closing = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() in ("---", "..."):
            closing = i
            break
    if closing is None:
        raise ValueError("SKILL.md frontmatter is not closed by a --- line")
    frontmatter = yaml.safe_load("".join(lines[1:closing]))
    if not isinstance(frontmatter, dict):
        raise ValueError("SKILL.md frontmatter must be a YAML mapping")
    return frontmatter, "".join(lines[closing + 1 :])


def load_skill(path: str | Path | None = None) -> Skill:
    """Load and validate the skill file. Raises FileNotFoundError / ValueError."""
    skill_path = Path(path) if path is not None else find_skill_file()
    raw = skill_path.read_bytes()
    if len(raw) > MAX_SKILL_BYTES:
        raise ValueError(f"SKILL.md is {len(raw)} bytes, over the 16 MiB skill limit")
    text = raw.decode("utf-8")
    frontmatter, _body = _parse_frontmatter(text)

    name = frontmatter.get("name")
    if name != SKILL_NAME:
        raise ValueError(
            f"SKILL.md frontmatter name is {name!r}, expected {SKILL_NAME!r} "
            "(the frontmatter name must match the skill directory name)"
        )
    if not frontmatter.get("description"):
        raise ValueError("SKILL.md frontmatter must contain a description")
    if "allowed-tools" in frontmatter:
        raise ValueError(
            "SKILL.md frontmatter must not contain allowed-tools: hosts must "
            "ignore it for MCP-origin skills, so it buys nothing and reads as "
            "a permission request (SEP-2640)"
        )
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    return Skill(
        name=SKILL_NAME,
        uri=SKILL_URI,
        frontmatter=frontmatter,
        text=text,
        raw=raw,
        digest=digest,
        size=len(raw),
    )


# ---------------------------------------------------------------------------
# Module-level cache: the skill is loaded once at server startup.
# ---------------------------------------------------------------------------

_skill: Skill | None = None


def get_skill_data(path: str | Path | None = None) -> Skill:
    """Return the loaded skill, loading it on first use (or reloading if a path is given)."""
    global _skill
    if _skill is None or path is not None:
        _skill = load_skill(path)
    return _skill


def list_skills() -> list[dict[str, Any]]:
    """SEP-2640 skills/list entries: the one skill this server serves."""
    return [get_skill_data().entry]


def get_skill(uri: str) -> dict[str, Any]:
    """SEP-2640 skills/get entry for a skill URI.

    Answers for the served skill even if it were ever left out of a
    listing. Raises ValueError for any other URI; the extension converts
    that to a -32602 Invalid params error.
    """
    skill = get_skill_data()
    if uri != skill.uri:
        raise ValueError(f"Unknown skill URI: {uri}")
    return skill.entry


# ---------------------------------------------------------------------------
# SEP-2640 wire types
# ---------------------------------------------------------------------------


class SkillsListParams(RequestParams):
    """skills/list request params (SEP-2640). Pagination cursor is optional."""

    cursor: str | None = None


class SkillsGetParams(RequestParams):
    """skills/get request params (SEP-2640). params.uri must be a skill's SKILL.md URI."""

    uri: str


# ---------------------------------------------------------------------------
# SEP-2133 extension: serves skills/list and skills/get, contributes the
# SKILL.md TextResource so resources/read serves the file.
# ---------------------------------------------------------------------------


class RelayShieldSkillsExtension(Extension):
    """The RelayShield Skills extension (SEP-2640) on the SDK's Extension mechanism."""

    identifier = SKILLS_EXTENSION_ID

    def __init__(self, skill: Skill | None = None) -> None:
        self._skill = skill if skill is not None else get_skill_data()

    def settings(self) -> dict[str, Any]:
        # The one SEP-2640 capability setting. directoryRead stays false:
        # the skill is a single file, there is nothing to navigate.
        return {"directoryRead": False}

    def resources(self) -> tuple[ResourceBinding, ...]:
        return (
            ResourceBinding(
                resource=TextResource(
                    uri=self._skill.uri,
                    name="SKILL.md",
                    title="RelayShield MCP Proxy Firewall skill",
                    mime_type="text/markdown",
                    text=self._skill.text,
                )
            ),
        )

    def methods(self) -> tuple[MethodBinding, ...]:
        return (
            MethodBinding(
                method="skills/list",
                params_type=SkillsListParams,
                handler=self._handle_list,
            ),
            MethodBinding(
                method="skills/get",
                params_type=SkillsGetParams,
                handler=self._handle_get,
            ),
        )

    async def _handle_list(
        self, ctx: ServerRequestContext[Any, Any], params: SkillsListParams
    ) -> dict[str, Any]:
        # Single skill, no pagination: cursor is accepted and ignored.
        return {"skills": [self._skill.entry]}

    async def _handle_get(
        self, ctx: ServerRequestContext[Any, Any], params: SkillsGetParams
    ) -> dict[str, Any]:
        if params.uri != self._skill.uri:
            raise MCPError(
                code=INVALID_PARAMS,
                message=f"Unknown skill URI: {params.uri}",
                data={"uri": params.uri},
            )
        return {"skill": self._skill.entry}


def build_skills_extension(path: str | Path | None = None) -> RelayShieldSkillsExtension:
    """Load the skill (once) and return the extension to pass to MCPServer."""
    return RelayShieldSkillsExtension(get_skill_data(path))
