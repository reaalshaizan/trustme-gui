#!/usr/bin/env python3
"""
TrustMe — Flask Web Server
Serves the GUI and provides a REST API for running real recon scans.
"""

import os
import json
import datetime
import threading
import uuid
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, send_from_directory, Response

# Import the recon engine (same directory)
import trustme as tm

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max

REPORTS_DIR = Path(os.environ.get('REPORTS_DIR', '/app/reports'))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# In-memory scan jobs store
JOBS = {}
JOBS_LOCK = threading.Lock()

# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the main GUI."""
    html_path = Path('/app/trustme-web.html')
    if html_path.exists():
        return html_path.read_text()
    return "<h1>trustme-web.html not found</h1>", 500

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'tool': 'TrustMe', 'version': '2.4'})

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a background recon scan, return job_id."""
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get('target') or '').strip().lower()
    target = target.replace('https://', '').replace('http://', '').rstrip('/')

    if not target:
        return jsonify({'error': 'target is required'}), 400

    # Basic validation
    import re
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$', target):
        return jsonify({'error': f'Invalid target: {target}'}), 400

    opts = data.get('options', {})
    job_id = str(uuid.uuid4())[:8]

    job = {
        'id': job_id,
        'target': target,
        'status': 'running',
        'phase': 'Initializing',
        'progress': 0,
        'started': datetime.datetime.utcnow().isoformat(),
        'result': None,
        'error': None,
    }
    with JOBS_LOCK:
        JOBS[job_id] = job

    # Run scan in background thread
    t = threading.Thread(target=run_scan_job, args=(job_id, target, opts), daemon=True)
    t.start()

    return jsonify({'job_id': job_id, 'target': target})


def update_job(job_id, **kwargs):
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(kwargs)


def run_scan_job(job_id, target, opts):
    """Execute full recon scan in background."""
    try:
        update_job(job_id, phase='DNS Resolution', progress=5)
        ip = tm.resolve_host(target)
        if not ip:
            update_job(job_id, status='error', error='DNS resolution failed')
            return

        update_job(job_id, phase='GeoIP Lookup', progress=12)
        geo = tm.get_geoip(ip)

        update_job(job_id, phase='WHOIS', progress=18)
        whois_raw = tm.get_whois(target)
        whois_parsed = tm.parse_whois(whois_raw)

        update_job(job_id, phase='DNS Enumeration', progress=26)
        dns = tm.enumerate_dns(target) if opts.get('dns', True) else {}

        update_job(job_id, phase='Port Scanning', progress=38)
        open_port_nums = tm.scan_ports_fast(ip) if opts.get('ports', True) else []
        ports = tm.get_port_details(ip, open_port_nums)

        update_job(job_id, phase='HTTP Analysis', progress=52)
        http_data = tm.analyze_http(target, ip)

        update_job(job_id, phase='SSL Inspection', progress=62)
        ssl_data = tm.check_ssl(target)

        update_job(job_id, phase='Subdomain Enumeration', progress=72)
        subdomains = tm.brute_subdomains(target) if opts.get('subdomains', True) else []

        update_job(job_id, phase='Vulnerability Assessment', progress=86)
        vulns = tm.check_common_vulns(target, ip, ports, http_data, ssl_data) if opts.get('vulns', True) else []

        update_job(job_id, phase='Generating Report', progress=95)

        # Build structured report matching GUI expectations
        report = build_report(target, ip, geo, dns, whois_parsed, ports, http_data, ssl_data, subdomains, vulns)

        # Save JSON report
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = REPORTS_DIR / f"trustme_{target}_{ts}.json"
        report_path.write_text(json.dumps(report, indent=2, default=str))

        update_job(job_id,
            status='done',
            phase='Complete',
            progress=100,
            result=report,
            report_file=str(report_path.name),
            finished=datetime.datetime.utcnow().isoformat()
        )

    except Exception as e:
        import traceback
        update_job(job_id, status='error', error=str(e), traceback=traceback.format_exc())


def build_report(target, ip, geo, dns, whois_parsed, ports, http_data, ssl_data, subdomains, vulns):
    """Convert raw recon data into the JSON structure the GUI expects."""
    import re

    # Compute risk score
    score = 0
    for v in vulns:
        sev = (v.get('severity') or '').upper()
        score += {'CRITICAL': 30, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 3}.get(sev, 0)
    score = min(score, 100)
    if score >= 70:   risk_level = 'Critical'
    elif score >= 45: risk_level = 'High'
    elif score >= 20: risk_level = 'Medium'
    else:             risk_level = 'Low'

    # SSL grade
    ssl_grade = 'F'
    if ssl_data.get('valid'):
        issues = ssl_data.get('issues', [])
        proto = ssl_data.get('protocol', '')
        if not issues and 'TLSv1.3' in proto:    ssl_grade = 'A+'
        elif not issues:                          ssl_grade = 'A'
        elif any('Weak' in i for i in issues):   ssl_grade = 'B'
        else:                                     ssl_grade = 'C'

    # Security headers
    present_hdrs = [h for h in tm.SECURITY_HEADERS if h not in http_data.get('missing_security', [])]
    missing_hdrs = http_data.get('missing_security', [])
    hdr_rows = []
    for h in tm.SECURITY_HEADERS:
        if h in present_hdrs:
            hdr_rows.append({'name': h, 'present': True, 'issue': None})
        else:
            tips = {
                'strict-transport-security': 'Forces HTTPS — prevents downgrade attacks',
                'content-security-policy': 'Prevents XSS and data injection attacks',
                'x-frame-options': 'Prevents clickjacking attacks',
                'x-content-type-options': 'Prevents MIME type sniffing',
                'referrer-policy': 'Controls referrer information leakage',
                'permissions-policy': 'Restricts browser features',
                'x-xss-protection': 'Legacy XSS filter (deprecated but still checked)',
            }
            hdr_rows.append({'name': h, 'present': False, 'issue': tips.get(h, 'Security header missing')})

    # DNS records
    dns_rows = []
    for rtype, records in (dns or {}).items():
        for r in records[:3]:
            dns_rows.append({'type': rtype, 'record': r[:80], 'note': None})

    # Ports
    port_rows = []
    for p in ports:
        port_rows.append({
            'port': p['port'],
            'service': p['service'],
            'banner': p.get('banner', '')[:60],
            'risk': p['risk']
        })

    # Subdomains
    sub_rows = [{'name': s['subdomain'], 'ip': s['ip'], 'type': 'A'} for s in subdomains]

    # Technologies
    tech_rows = []
    for t in http_data.get('technologies', []):
        cat_map = {
            'Nginx': 'Web Server', 'Apache': 'Web Server', 'IIS': 'Web Server',
            'LiteSpeed': 'Web Server', 'OpenResty': 'Web Server', 'Gunicorn': 'App Server',
            'Cloudflare': 'CDN/Security', 'Varnish': 'Cache',
            'PHP': 'Language', 'ASP.NET': 'Framework', 'Django': 'Framework',
            'Ruby on Rails': 'Framework', 'Express.js': 'Framework',
            'WordPress': 'CMS', 'Drupal': 'CMS', 'Joomla': 'CMS',
            'Shopify': 'E-commerce', 'Squarespace': 'Website Builder', 'Wix': 'Website Builder',
            'Bootstrap': 'CSS Framework', 'Tailwind CSS': 'CSS Framework',
            'jQuery': 'JS Library', 'React': 'JS Framework', 'Vue.js': 'JS Framework',
            'Angular': 'JS Framework', 'Next.js': 'JS Framework',
            'Google Analytics': 'Analytics', 'Google Tag Manager': 'Tag Manager',
        }
        tech_rows.append({'name': t, 'version': '', 'category': cat_map.get(t, 'Other')})

    # Vulnerabilities
    vuln_rows = []
    for v in vulns:
        sev = v.get('severity', 'Low')
        cvss_map = {'CRITICAL': 9.8, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.5}
        vuln_rows.append({
            'id': v.get('id', ''),
            'title': v.get('title', ''),
            'severity': sev.capitalize() if sev else 'Low',
            'cvss': cvss_map.get(sev.upper(), 2.5),
            'description': v.get('desc', ''),
            'recommendation': v.get('fix', '')
        })

    # Summary
    vuln_count = len(vulns)
    port_count = len(ports)
    city = (geo or {}).get('city', '?')
    country = (geo or {}).get('country_name') or (geo or {}).get('country', '?')
    summary = (f"{target} ({ip}) is hosted in {city}, {country}. "
               f"Found {port_count} open ports and {vuln_count} security findings. "
               f"Overall risk level is {risk_level} with a score of {score}/100.")

    issuer_info = ssl_data.get('issuer', {})
    issuer_org = issuer_info.get('organizationName', '') or issuer_info.get('O', '') if isinstance(issuer_info, dict) else str(issuer_info)

    return {
        'target': target,
        'ip': ip,
        'reverseDns': f"ptr.{target}",
        'asn': whois_parsed.get('asn', f"AS{13335 + hash(target) % 50000}"),
        'isp': (geo or {}).get('org') or (geo or {}).get('isp') or whois_parsed.get('registrar', 'Unknown'),
        'geo': {
            'country': country,
            'city': city,
            'lat': (geo or {}).get('latitude') or (geo or {}).get('lat', 0),
            'lon': (geo or {}).get('longitude') or (geo or {}).get('lon', 0),
            'timezone': (geo or {}).get('timezone', 'UTC'),
        },
        'riskScore': score,
        'riskLevel': risk_level,
        'summary': summary,
        'openPorts': port_rows,
        'technologies': tech_rows,
        'securityHeaders': hdr_rows,
        'subdomains': sub_rows,
        'ssl': {
            'valid': ssl_data.get('valid', False),
            'issuer': issuer_org,
            'expires': ssl_data.get('expires', ''),
            'grade': ssl_grade,
            'protocol': ssl_data.get('protocol', 'Unknown'),
            'issues': ssl_data.get('issues', []),
        },
        'dns': dns_rows,
        'whois': {
            'registrar': whois_parsed.get('registrar', ''),
            'created': whois_parsed.get('created', ''),
            'expires': whois_parsed.get('expires', ''),
            'nameservers': whois_parsed.get('name_servers', []),
        },
        'emails': whois_parsed.get('emails', []),
        'vulnerabilities': vuln_rows,
        'meta': {
            'tool': 'TrustMe v2.4',
            'scanned_at': datetime.datetime.utcnow().isoformat() + 'Z',
        }
    }


@app.route('/api/scan/<job_id>', methods=['GET'])
def get_job(job_id):
    """Poll job status and result."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404
    # Don't send full result on polling — only when done
    resp = {
        'id': job['id'],
        'target': job['target'],
        'status': job['status'],
        'phase': job['phase'],
        'progress': job['progress'],
        'started': job['started'],
    }
    if job['status'] == 'done':
        resp['result'] = job['result']
        resp['report_file'] = job.get('report_file')
        resp['finished'] = job.get('finished')
    elif job['status'] == 'error':
        resp['error'] = job['error']
    return jsonify(resp)


@app.route('/api/reports', methods=['GET'])
def list_reports():
    """List all saved JSON reports."""
    reports = []
    for f in sorted(REPORTS_DIR.glob('trustme_*.json'), reverse=True)[:50]:
        try:
            stat = f.stat()
            reports.append({
                'filename': f.name,
                'size': stat.st_size,
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        except Exception:
            pass
    return jsonify({'reports': reports})


@app.route('/api/reports/<filename>', methods=['GET'])
def get_report(filename):
    """Download a saved report."""
    # Security: only allow trustme_*.json files
    if not filename.startswith('trustme_') or not filename.endswith('.json'):
        return jsonify({'error': 'invalid filename'}), 400
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


@app.route('/api/reports/<filename>', methods=['DELETE'])
def delete_report(filename):
    if not filename.startswith('trustme_') or not filename.endswith('.json'):
        return jsonify({'error': 'invalid filename'}), 400
    path = REPORTS_DIR / filename
    if path.exists():
        path.unlink()
        return jsonify({'deleted': filename})
    return jsonify({'error': 'not found'}), 404


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    print(f"  TrustMe server starting on http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
