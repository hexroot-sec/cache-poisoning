#!/usr/bin/env python3
# Lab do Cache Poisoning Hunter — emula CDN:
#   CHAVE = path + params zzcp* (o cache-buster) — headers NÃO entram na chave.
#   /          X-Forwarded-Host refletido em <script src> e canonical (XSS primitive)
#              X-Original-URL presente → 301 /landing?h=... (redirect poisoning)
#              X-HTTP-Method-Override presente → 405 (CPDoS)
#   /landing   página normal
#   /nocache   Cache-Control: no-store (controle negativo)
import http.server, socketserver, urllib.parse, time

CACHE = {}  # key -> (status, headers_dict, body_bytes)

def qs(q):
    return urllib.parse.parse_qs(q)

def cache_key(path, q):
    # só os params zzcp* entram na chave (são o cache-buster) — NOME E VALOR,
    # como um cache real (chave = query string completa).
    # zzcpQ usa o ÚLTIMO valor (emula cache que chaveia a última ocorrência de
    # param duplicado, enquanto o backend usa a primeira → cloaking)
    bust = sorted('%s=%s' % (k, qs(q)[k][-1]) for k in qs(q) if k.startswith('zzcp'))
    return path + '?' + '&'.join(bust)

def build(path, q, headers):
    xfh = headers.get('X-Forwarded-Host')
    xou = headers.get('X-Original-URL')
    xmo = headers.get('X-HTTP-Method-Override')
    if path == '/':
        if xmo is not None:
            return 405, {'Content-Type': 'text/plain'}, ('Not Allowed (override=%s)' % xmo).encode()
        if xou is not None:
            return 301, {'Location': '/landing?h=' + xou}, b''
        body = '<!doctype html><meta charset=utf-8><title>cp lab</title>\n'
        if xfh is not None:
            # ESI emulado: se o header refletido traz tag <esi:include>, o edge
            # "processa" (substitui a tag) — como um CDN com ESI ativo
            if '<esi:include' in xfh:
                xfh = 'ESI-EXECUTADO:' + xfh.split('src="')[1].split('"')[0]
            body += '<script src="//%s/x.js"></script>\n' % xfh
            body += '<link rel="canonical" href="https://%s/">\n' % xfh
        # param duplicado zzcpQ: backend usa o PRIMEIRO valor (cloaking)
        v = q.get('zzcpQ')
        if v:
            body += '<p id="q">zzcpQ=%s</p>\n' % v[0]
        body += '<h1>cache poisoning lab</h1>'
        return 200, {'Content-Type': 'text/html; charset=utf-8'}, body.encode()
    if path == '/landing':
        return 200, {'Content-Type': 'text/plain'}, b'landing page'
    return 404, {'Content-Type': 'text/plain'}, b'not found'

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = qs(u.query)
        if u.path == '/nocache':
            body = b'<h1>sem cache</h1>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if any(k.startswith('zzcp') for k in q):
            key = cache_key(u.path, u.query)
            if key in CACHE:
                status, hdrs, body = CACHE[key]
                self.send_response(status)
                hdrs['X-Cache'] = 'HIT'
                hdrs['Age'] = '60'
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            status, hdrs, body = build(u.path, q, self.headers)
            CACHE[key] = (status, dict(hdrs), body)
            self.send_response(status)
            hdrs['X-Cache'] = 'MISS'
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # sem buster: direto na origem, sem cache
        status, hdrs, body = build(u.path, q, self.headers)
        self.send_response(status)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print('[cp-lab]', fmt % args)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True  # evita TIME_WAIT no rebind
    with socketserver.ThreadingTCPServer(('127.0.0.1', 8767), H) as httpd:
        print('cp-lab em http://127.0.0.1:8767 (chave = zzcp* params; headers unkeyed)', flush=True)
        httpd.serve_forever()
