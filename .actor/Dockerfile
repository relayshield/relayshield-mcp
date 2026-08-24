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
RUN pip install --no-cache-dir "fastmcp>=3,<4" "apify>=2,<3" "uvicorn>=0.30"

COPY .actor/src ./actor_src

ENV RELAYSHIELD_API_URL=""
ENV RELAYSHIELD_API_KEY=""
ENV RELAYSHIELD_X_PAYMENT=""

CMD ["python", "actor_src/main.py"]
