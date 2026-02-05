FROM python:3.12.4-alpine
LABEL Maintainer="LRVT"

# Install build dependencies for Python packages with C extensions
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    python3-dev \
    build-base \
    libxml2-dev \
    libxslt-dev \
    openssl

# Enable legacy OpenSSL algorithms (required for MD4/NTLM)
RUN sed -i 's/\[openssl_init\]/[openssl_init]\nssl_conf = ssl_sect\n\n[ssl_sect]\nsystem_default = system_default_sect\n\n[system_default_sect]\nCipherString = DEFAULT@SECLEVEL=0/' /etc/ssl/openssl.cnf || \
    echo -e '\n[openssl_init]\nssl_conf = ssl_sect\n\n[ssl_sect]\nsystem_default = system_default_sect\n\n[system_default_sect]\nCipherString = DEFAULT@SECLEVEL=0' >> /etc/ssl/openssl.cnf

# Alternative: Create OpenSSL config to enable legacy providers (Python 3.12)
RUN echo '[provider_sect]' > /etc/ssl/legacy.cnf && \
    echo 'default = default_sect' >> /etc/ssl/legacy.cnf && \
    echo 'legacy = legacy_sect' >> /etc/ssl/legacy.cnf && \
    echo '[default_sect]' >> /etc/ssl/legacy.cnf && \
    echo 'activate = 1' >> /etc/ssl/legacy.cnf && \
    echo '[legacy_sect]' >> /etc/ssl/legacy.cnf && \
    echo 'activate = 1' >> /etc/ssl/legacy.cnf

# Set environment variable to use legacy OpenSSL config
ENV OPENSSL_CONF=/etc/ssl/legacy.cnf

COPY requirements.txt pyadrecon.py /app/
RUN pip3 install --no-cache-dir -r /app/requirements.txt

WORKDIR /app
ENTRYPOINT ["python", "pyadrecon.py"]

CMD ["python", "pyadrecon.py", "--help"]
