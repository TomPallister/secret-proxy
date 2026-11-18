FROM python:3.13-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6

# The base digest fixes the starting filesystem, but Debian apt repositories
# remain mutable. Package layers are not bit-for-bit reproducible until a dated
# snapshot or exact package-version policy is adopted.

# Pinned tool versions (no :latest).
ENV UV_VERSION=0.8.17
ENV OP_CLI_VERSION=2.39.0
ENV SAML2AWS_VERSION=2.36.19

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl \
      ca-certificates \
      xz-utils \
      unzip \
      iproute2 \
      jq \
      oathtool \
      socat \
    && rm -rf /var/lib/apt/lists/* \
    && oathtool --version | head -1

# uv — pinned official binary, checksum-verified, arch-aware. Runtime Python
# dependencies are installed only from the committed lockfile below.
RUN --mount=type=secret,id=upstream_ca set -eux; \
    if [ -f /run/secrets/upstream_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/upstream_ca > /tmp/build-ca.pem; \
      export CURL_CA_BUNDLE=/tmp/build-ca.pem; \
    fi; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      arm64) uvarch='aarch64'; sha='9a20d65b110770bbaa2ee89ed76eb963d8c6a480b9ebef584ea9df2ae85b4f0f' ;; \
      amd64) uvarch='x86_64';  sha='920cbcaad514cc185634f6f0dcd71df5e8f4ee4456d440a22e0f8c0f142a8203' ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    archive="uv-${uvarch}-unknown-linux-gnu.tar.gz"; \
    curl -fsSLo "/tmp/${archive}" "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${archive}"; \
    echo "${sha}  /tmp/${archive}" | sha256sum -c -; \
    mkdir /tmp/uv; \
    tar -xzf "/tmp/${archive}" -C /tmp/uv --strip-components=1; \
    install -m 0755 /tmp/uv/uv /usr/local/bin/uv; \
    rm -rf /tmp/uv "/tmp/${archive}"; \
    test "$(uv --version | awk '{print $2}')" = "$UV_VERSION" \
    && rm -f /tmp/build-ca.pem

WORKDIR /opt/secret-proxy
COPY pyproject.toml uv.lock ./
ENV UV_PYTHON_DOWNLOADS=never UV_NO_CACHE=1
RUN --mount=type=secret,id=upstream_ca set -eu; \
    if [ -f /run/secrets/upstream_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/upstream_ca > /tmp/build-ca.pem; \
      export SSL_CERT_FILE=/tmp/build-ca.pem UV_NATIVE_TLS=true; \
    fi; \
    uv sync --locked --no-dev --no-install-project; \
    .venv/bin/mitmdump --version; \
    rm -f /tmp/build-ca.pem

# 1Password CLI — pinned official Linux artifact, checksum-verified, arch-aware.
RUN --mount=type=secret,id=upstream_ca set -eux; \
    if [ -f /run/secrets/upstream_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/upstream_ca > /tmp/build-ca.pem; \
      export CURL_CA_BUNDLE=/tmp/build-ca.pem; \
    fi; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      arm64) url="https://cache.agilebits.com/dist/1P/op2/pkg/v${OP_CLI_VERSION}/op_linux_arm64_v${OP_CLI_VERSION}.zip"; sha='829baeff1c07e055cfa132031b1d9f2282ccdf5076258e482caf2fda70aea5d0' ;; \
      amd64) url="https://cache.agilebits.com/dist/1P/op2/pkg/v${OP_CLI_VERSION}/op_linux_amd64_v${OP_CLI_VERSION}.zip"; sha='6fba7f376b6c6dec49f41b06408930a43ad064cce103c6a2ce5b3d0413a86434' ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/op.zip "$url"; \
    echo "${sha}  /tmp/op.zip" | sha256sum -c -; \
    unzip -q /tmp/op.zip -d /tmp/op; \
    install -m 0755 /tmp/op/op /usr/local/bin/op; \
    rm -rf /tmp/op /tmp/op.zip; \
    test "$(op --version)" = "${OP_CLI_VERSION}" \
    && rm -f /tmp/build-ca.pem

# saml2aws: pinned and checksum-verified for both architectures.
RUN --mount=type=secret,id=upstream_ca set -eux; \
    if [ -f /run/secrets/upstream_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/upstream_ca > /tmp/build-ca.pem; \
      export CURL_CA_BUNDLE=/tmp/build-ca.pem; \
    fi; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      arm64) s2aarch='arm64'; sha='b62424836c8ebd41dca312f3385a7ed552b48dafd4c49d47f62bbef428633255' ;; \
      amd64) s2aarch='amd64'; sha='891f7d0eb89bb3000aca72f70ef244ea5f24894f33b24143203caa528555ad7f' ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/s2a.tar.gz "https://github.com/Versent/saml2aws/releases/download/v${SAML2AWS_VERSION}/saml2aws_${SAML2AWS_VERSION}_linux_${s2aarch}.tar.gz"; \
    echo "${sha}  /tmp/s2a.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/s2a.tar.gz -C /usr/local/bin saml2aws; \
    rm /tmp/s2a.tar.gz; \
    chmod +x /usr/local/bin/saml2aws; \
    saml2aws --version \
    && rm -f /tmp/build-ca.pem

# Explicit source allowlist: never copy private configuration or certificates.
COPY addon.py entry.py sigv4.py awscreds.py googlecreds.py auth0creds.py oauthcreds.py chatgptcreds.py sealedjwt.py gitsign.py secretstore.py runtime.py /opt/secret-proxy/
RUN useradd --uid 1000 --create-home --shell /bin/bash secretproxy \
    && mkdir -p /data/mitmproxy /run/secret-proxy \
    && chown -R 1000:1000 /data /run/secret-proxy
USER secretproxy
WORKDIR /opt/secret-proxy
ENTRYPOINT ["/opt/secret-proxy/.venv/bin/python", "/opt/secret-proxy/runtime.py"]
