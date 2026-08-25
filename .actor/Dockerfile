FROM python:3.12-slim

WORKDIR /app

# Build relayshield-mcp from this repo's own source, not a possibly-stale
# PyPI release -- the root Dockerfile pins an old published version for a
# different use case (a plain stdio container); this one always ships
# whatever is on this branch.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Proxy/runtime deps for wrapping the stdio server over Streamable HTTP.
# apify>=2,<3 (and the crawlee 0.6.x it pulls in) crashes on import against
# the pydantic version fastmcp requires -- crawlee's HttpHeaders model hits
# "cannot specify both default and default_factory". apify>=4,<5 pulls in
# crawlee>=1.x, which is built against current pydantic and actually imports.
# Verified 2026-08-25: apify>=2,<3 crash-loops 100% of real Standby runs.
RUN pip install --no-cache-dir "fastmcp>=3,<4" "apify>=4,<5" "uvicorn>=0.30"

COPY .actor/src ./actor_src

ENV RELAYSHIELD_API_URL=""
ENV RELAYSHIELD_API_KEY=""
ENV RELAYSHIELD_X_PAYMENT=""

CMD ["python", "actor_src/main.py"]
