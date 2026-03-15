FROM python:3.11-slim

LABEL maintainer="TrustMe"
LABEL description="TrustMe — Automated Web Reconnaissance Tool"
LABEL version="2.4"

# Install system recon tools + su-exec for clean privilege drop
RUN apt-get update && apt-get install -y --no-install-recommends \
    whois \
    dnsutils \
    nmap \
    curl \
    iputils-ping \
    net-tools \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY app/ .

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Create trustme user and set ownership
RUN useradd -m -u 1000 trustme \
    && mkdir -p /app/reports \
    && chown -R trustme:trustme /app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run as root so entrypoint can fix volume permissions, then drops to trustme
ENTRYPOINT ["/app/entrypoint.sh"]
