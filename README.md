# TrustMe — Docker Deployment

```
  ████████╗██████╗ ██╗   ██╗███████╗████████╗███╗   ███╗███████╗
     ██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝████╗ ████║██╔════╝
     ██║   ██████╔╝██║   ██║███████╗   ██║   ██╔████╔██║█████╗
     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══╝
     ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║███████╗
     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝
```

Automated web reconnaissance platform. Full GUI, REST API, persistent reports — runs entirely in Docker on your Linux server.

---

## Quick Start (3 commands)

```bash
chmod +x manage.sh
./manage.sh build
./manage.sh up
```

Then open **http://localhost:8080** in your browser.

---

## Requirements

- Docker Engine 20.10+
- Docker Compose v2 (or docker-compose v1)
- Linux (Ubuntu/Debian/Fedora/Arch — any distro)

**Install Docker on Ubuntu/Debian:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

---

## File Structure

```
trustme-docker/
├── Dockerfile              ← Python 3.11 + recon tools (nmap, whois, dig)
├── docker-compose.yml      ← Service definition
├── requirements.txt        ← Flask + Gunicorn
├── manage.sh               ← Management helper script
├── .env.example            ← Environment config template
├── nginx/
│   └── nginx.conf          ← Reverse proxy config (optional)
├── app/
│   ├── server.py           ← Flask web server + REST API
│   ├── trustme.py          ← Recon engine
│   └── trustme-web.html    ← GUI frontend
└── reports/                ← Saved JSON reports (auto-created)
```

---

## Management Commands

```bash
./manage.sh build      # Build Docker image
./manage.sh up         # Start on port 8080 (background)
./manage.sh down       # Stop
./manage.sh restart    # Restart
./manage.sh logs       # Tail live logs
./manage.sh status     # Health check + report count
./manage.sh shell      # Open bash inside container
./manage.sh reports    # List saved reports
./manage.sh clean      # Remove containers & images (keeps reports)
./manage.sh update     # Rebuild + restart
./manage.sh prod       # Start with Nginx on port 80
```

---

## Configuration

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
```

```env
PORT=8080          # Host port for the web UI
NGINX_PORT=80      # Nginx port (production only)
DEBUG=false        # Never true in production
```

Run on a custom port:
```bash
PORT=9090 ./manage.sh up
```

---

## REST API

The Flask backend exposes a full REST API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/` | Web GUI |
| `GET`  | `/health` | Health check |
| `POST` | `/api/scan` | Start a scan job |
| `GET`  | `/api/scan/:job_id` | Poll job status/result |
| `GET`  | `/api/reports` | List saved reports |
| `GET`  | `/api/reports/:filename` | Download report |
| `DELETE` | `/api/reports/:filename` | Delete report |

**Start a scan:**
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "options": {"ports": true, "subdomains": true, "vulns": true}}'
```

**Poll for results:**
```bash
curl http://localhost:8080/api/scan/<job_id>
```

**List reports:**
```bash
curl http://localhost:8080/api/reports
```

---

## Production with Nginx (port 80)

```bash
./manage.sh prod
```

This starts both the Flask app and Nginx reverse proxy. Nginx handles:
- Connection pooling / keepalive
- Gzip compression
- Security headers
- Long timeout for scan requests (300s)

---

## Reports

All completed scans are saved as JSON files in `./reports/` on your host (volume-mounted into the container). They persist across restarts and rebuilds.

```bash
# List reports
./manage.sh reports

# View a report
cat reports/trustme_example.com_20250315_143022.json | python3 -m json.tool

# Download via API
curl -O http://localhost:8080/api/reports/trustme_example.com_20250315_143022.json
```

---

## What Gets Scanned

| Module | Details |
|--------|---------|
| Port Scan | 28 common TCP ports, parallel, with banner grabbing |
| GeoIP | Country, city, ISP, ASN, timezone |
| DNS | A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA |
| WHOIS | Registrar, dates, nameservers, emails |
| Subdomains | 60+ common names, concurrent resolution |
| HTTP | Status, server, title, technology fingerprinting |
| SSL/TLS | Certificate validity, issuer, expiry, protocol grade |
| Security Headers | 7 headers audited for presence/correctness |
| Vulnerabilities | Port-based CVEs, exposed paths (.env, .git, phpinfo...) |

---

## Troubleshooting

**Port already in use:**
```bash
PORT=9090 ./manage.sh up
```

**Nmap requires elevated capabilities:**
The container is granted `NET_RAW` and `NET_ADMIN` capabilities in `docker-compose.yml`. This is required for nmap's ICMP-based host discovery. If you're on a restrictive host, scans still work via TCP without these caps.

**Scan times out:**
Large subdomain wordlists or slow targets can take 2–3 minutes. The API keeps the job alive — just keep polling.

**View detailed logs:**
```bash
./manage.sh logs
```

---

## Legal Notice

> ⚠️ **Only scan systems you own or have explicit written authorization to test.**
> Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, or equivalent laws in your jurisdiction. The authors accept no liability for misuse.
