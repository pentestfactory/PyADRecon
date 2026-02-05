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
    libxslt-dev

COPY requirements.txt pyadrecon.py /app/
RUN pip3 install --no-cache-dir -r /app/requirements.txt

WORKDIR /app
ENTRYPOINT ["python", "pyadrecon.py"]

CMD ["python", "pyadrecon.py", "--help"]
