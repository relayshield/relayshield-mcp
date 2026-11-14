"""SEP-2640 Skills extension tests for the RelayShield free MCP server.

Covers the shared skills module (relayshield_free.skills) and the
extension wiring on the MCPServer:
  - skills/list returns the one entry with correct frontmatter, URI,
    digest, and size
  - skills/get returns the same entry
  - skills/get on an unknown URI returns -32602 (Invalid params)
  - the served bytes hash to the advertised digest
  - the frontmatter name equals the final URI segment

The wire-level checks (initialize capabilities, skills/list and
skills/get over stdio and HTTP) are exercised by the probe scripts;
these tests cover the same behaviour in-process.

Run: PYTHONPATH=src pytest tests/ -q
"""

import asyncio
import hashlib

import pytest
from mcp.shared.exceptions import MCPError

from relayshield_free import server as free_server
from relayshield_free.skills import (
    SKILL_NAME,
    SKILL_URI,
    SkillsGetParams,
    SkillsListParams,
    build_skills_extension,
    get_skill,
    list_skills,
    load_skill,
)


def _entry():
    return list_skills()[0]


def test_skill_file_loads_with_frontmatter():
    skill = load_skill()
    assert skill.name == SKILL_NAME
    assert skill.uri == SKILL_URI
    assert skill.frontmatter["name"] == SKILL_NAME
    assert skill.frontmatter["description"], "frontmatter needs a description"
    assert skill.frontmatter["license"] == "MIT"
    assert skill.frontmatter["metadata"]["author"] == "RelayShield"
    assert skill.frontmatter["metadata"]["version"] == "1.0.0"
    # SEP-2640: hosts must ignore allowed-tools for MCP-origin skills, so
    # we must not publish it.
    assert "allowed-tools" not in skill.frontmatter
    assert skill.size == len(skill.raw)
    assert skill.digest == "sha256:" + hashlib.sha256(skill.raw).hexdigest()
    assert skill.text == skill.raw.decode("utf-8")


def test_frontmatter_name_matches_uri_segment():
    # The final <skill-path> segment of the URI must equal the frontmatter name.
    segments = SKILL_URI.removeprefix("skill://").split("/")
    assert segments[-1] == "SKILL.md"
    assert segments[-2] == SKILL_NAME
    assert load_skill().frontmatter["name"] == segments[-2]


def test_list_skills_returns_one_entry():
    skills = list_skills()
    assert len(skills) == 1
    entry = skills[0]
    assert entry["uri"] == SKILL_URI
    assert entry["frontmatter"]["name"] == SKILL_NAME
    assert entry["frontmatter"] == load_skill().frontmatter
    resources = entry["resources"]
    assert len(resources) == 1
    assert resources[0]["uri"] == SKILL_URI
    assert resources[0]["digest"] == load_skill().digest
    assert resources[0]["size"] == load_skill().size


def test_get_skill_returns_same_entry():
    assert get_skill(SKILL_URI) == _entry()


def test_get_skill_unknown_uri_raises():
    with pytest.raises(ValueError, match="Unknown skill URI"):
        get_skill("skill://does-not-exist/SKILL.md")


def test_extension_list_returns_entry():
    ext = build_skills_extension()
    result = asyncio.run(ext._handle_list(None, SkillsListParams()))
    assert result["skills"] == [_entry()]


def test_extension_get_unknown_uri_returns_32602():
    ext = build_skills_extension()
    with pytest.raises(MCPError) as excinfo:
        asyncio.run(ext._handle_get(None, SkillsGetParams(uri="skill://nope/SKILL.md")))
    assert excinfo.value.code == -32602


def test_extension_advertises_skills_identifier():
    ext = build_skills_extension()
    assert ext.identifier == "io.modelcontextprotocol/skills"
    assert ext.settings() == {"directoryRead": False}
    assert [m.method for m in ext.methods()] == ["skills/list", "skills/get"]
    assert [r.resource.uri for r in ext.resources()] == [SKILL_URI]


def test_server_lists_skill_resource():
    resources = asyncio.run(free_server.mcp.list_resources())
    uris = [r.uri for r in resources]
    assert SKILL_URI in uris
    skill_resource = [r for r in resources if r.uri == SKILL_URI][0]
    assert skill_resource.mime_type == "text/markdown"


def test_served_bytes_hash_to_advertised_digest():
    # Read the skill through the server's resources/read path and verify
    # the bytes hash to the digest in the skills/list manifest.
    contents = asyncio.run(free_server.mcp.read_resource(SKILL_URI))
    assert len(contents) == 1
    text = contents[0].content
    assert isinstance(text, str)
    assert text == load_skill().text
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == load_skill().digest.removeprefix("sha256:")
    assert len(text.encode("utf-8")) == load_skill().size
    assert len(text.encode("utf-8")) == _entry()["resources"][0]["size"]


def test_server_capabilities_include_skills_extension():
    # In-process capabilities (the object the server hands to initialize):
    # the extension settings and the resources capability must both be there.
    # NOTE: on the 2025-11-25 handshake wire the SDK's version sieve drops
    # the extensions field (it only exists in the 2026-07-28 revision), so a
    # 2025-11-25 initialize response shows resources but not extensions.
    # skills/list and skills/get still work on that connection.
    caps = free_server.mcp._lowlevel_server.get_capabilities()
    assert caps.extensions == {"io.modelcontextprotocol/skills": {"directoryRead": False}}
    assert caps.resources is not None
