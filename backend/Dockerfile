FROM python:3.12-slim

# c2patool (C2PA reference CLI) — pinned release, checked at build time.
ARG C2PATOOL_VERSION=0.27.23
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL -o /tmp/c2patool.tgz \
       "https://github.com/contentauth/c2pa-rs/releases/download/c2patool-v${C2PATOOL_VERSION}/c2patool-v${C2PATOOL_VERSION}-x86_64-unknown-linux-gnu.tar.gz" \
    && mkdir -p /tmp/c2p && tar -xzf /tmp/c2patool.tgz -C /tmp/c2p \
    && install -m 0755 "$(find /tmp/c2p -type f -name c2patool | head -n1)" /usr/local/bin/c2patool \
    && rm -rf /tmp/c2patool.tgz /tmp/c2p \
    && c2patool --version \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
