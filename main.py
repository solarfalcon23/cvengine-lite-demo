import json, socket, urllib.request

COMMON = ['www', 'api', 'dev', 'staging', 'admin']
SEC_HEADERS = ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'x-frame-options']

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None

def probe(host):
    url = f'https://{host}'
    req = urllib.request.Request(url, method='GET', headers={'User-Agent': 'CVEngine-demo/0.1'})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
            return {
                'url': url,
                'status': r.status,
                'server': headers.get('server', ''),
                'missing_security_headers': [h for h in SEC_HEADERS if h not in headers],
            }
    except Exception as e:
        return {'url': url, 'error': str(e)}

def main(domain):
    findings = []
    for sub in COMMON:
        host = f'{sub}.{domain}'
        ip = resolve(host)
        if ip:
            finding = probe(host)
            finding['host'] = host
            finding['ip'] = ip
            findings.append(finding)
    print(json.dumps({'domain': domain, 'findings': findings}, indent=2))

if __name__ == '__main__':
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else 'example.com')