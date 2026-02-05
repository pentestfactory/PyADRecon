FROM python:3.12.4-slim
LABEL Maintainer="LRVT"

# Install build dependencies for Python packages with C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    python3-dev \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure OpenSSL to enable legacy providers (required for MD4/NTLM)
RUN mkdir -p /etc/ssl && \
    cat > /etc/ssl/openssl.cnf <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
EOF

# Set environment variable to use legacy OpenSSL config
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf

COPY requirements.txt pyadrecon.py /app/
RUN pip3 install --no-cache-dir -r /app/requirements.txt

WORKDIR /app
ENTRYPOINT ["python", "pyadrecon.py"]
