#!/usr/bin/env node
/**
 * RuView local HTTPS server — iPhone X-Ray dashboard access.
 *
 * - Serves the ui/ directory over HTTPS on port 8443 (LAN-accessible).
 * - Proxies WebSocket /ws/* to the Rust sensing server on ws://localhost:8765.
 * - Generates a self-signed cert on first run (requires openssl from Git for Windows).
 * - Prints iPhone cert-install instructions and a QR-code URL on startup.
 *
 * Usage:
 *   node scripts/serve-https.js
 *   node scripts/serve-https.js --port 8443 --ws-port 8765 --regen-cert
 */

'use strict';
const https  = require('https');
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const net    = require('net');
const os     = require('os');
const { execFileSync } = require('child_process');

// ─── CLI args ─────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const arg  = (name, def) => { const i = argv.indexOf(name); return i !== -1 && argv[i+1] ? argv[i+1] : def; };
const PORT        = parseInt(arg('--port', '8443'));
const WS_HOST     = arg('--ws-host', '127.0.0.1');
const WS_PORT     = parseInt(arg('--ws-port', '8765'));
const REGEN       = argv.includes('--regen-cert');

const ROOT      = path.resolve(__dirname, '..');
const UI_DIR    = path.join(ROOT, 'ui');
const CERTS_DIR = path.join(ROOT, 'certs');
const CERT_FILE = path.join(CERTS_DIR, 'ruview-local.crt');
const KEY_FILE  = path.join(CERTS_DIR, 'ruview-local.key');

// ─── Local IPv4 ───────────────────────────────────────────────────────────────
function localIP() {
    for (const ifaces of Object.values(os.networkInterfaces())) {
        for (const i of ifaces) {
            if (i.family === 'IPv4' && !i.internal) return i.address;
        }
    }
    return '127.0.0.1';
}

// ─── Find openssl (bundled with Git for Windows) ──────────────────────────────
function findOpenssl() {
    const candidates = [
        'openssl',
        'C:\\Program Files\\Git\\usr\\bin\\openssl.exe',
        'C:\\Program Files (x86)\\Git\\usr\\bin\\openssl.exe',
        path.join(process.env.LOCALAPPDATA || '', 'Programs', 'Git', 'usr', 'bin', 'openssl.exe'),
        path.join(process.env.ProgramFiles  || '', 'Git', 'usr', 'bin', 'openssl.exe'),
    ];
    for (const c of candidates) {
        try { execFileSync(c, ['version'], { stdio: 'pipe' }); return c; } catch {}
    }
    return null;
}

// ─── Certificate generation ───────────────────────────────────────────────────
function generateCert(ip) {
    const ssl = findOpenssl();
    if (!ssl) {
        console.error('\n❌  openssl not found.\n    Install Git for Windows (https://gitforwindows.org/) and re-run.\n');
        process.exit(1);
    }
    if (!fs.existsSync(CERTS_DIR)) fs.mkdirSync(CERTS_DIR, { recursive: true });

    console.log(`\n🔐  Generating self-signed certificate for ${ip}…`);
    const san = `IP:${ip},IP:127.0.0.1,DNS:localhost`;
    execFileSync(ssl, [
        'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', KEY_FILE,
        '-out',    CERT_FILE,
        '-days',   '397',
        '-nodes',
        '-subj',   `/CN=ruview.local/O=RuView`,
        '-addext', `subjectAltName=${san}`,
    ], { stdio: 'pipe' });
    console.log(`✅  Certificate → certs/ruview-local.crt\n`);
}

// ─── MIME types ───────────────────────────────────────────────────────────────
const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js':   'application/javascript; charset=utf-8',
    '.mjs':  'application/javascript; charset=utf-8',
    '.css':  'text/css; charset=utf-8',
    '.json': 'application/json',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.svg':  'image/svg+xml',
    '.ico':  'image/x-icon',
    '.wasm': 'application/wasm',
    '.crt':  'application/x-x509-ca-cert',   // iOS will offer to install cert
    '.pem':  'application/x-pem-file',
};

// ─── Static file handler ──────────────────────────────────────────────────────
function serveFile(res, filePath, allowedRoot) {
    const safe = path.resolve(filePath);
    const root = allowedRoot || UI_DIR;
    if (!safe.startsWith(root)) { res.writeHead(403); res.end(); return; }

    if (!fs.existsSync(safe)) { res.writeHead(404); res.end('Not found'); return; }
    if (fs.statSync(safe).isDirectory()) {
        return serveFile(res, path.join(safe, 'index.html'));
    }
    const ext = path.extname(safe).toLowerCase();
    res.writeHead(200, {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Cache-Control': 'no-cache',
    });
    fs.createReadStream(safe).pipe(res);
}

const HTTP_PORT = parseInt(arg('--http-port', '8080'));

// Proxy REST API calls to the Rust sensing server over plain HTTP.
function proxyApi(req, res) {
    const opts = {
        hostname: WS_HOST, port: HTTP_PORT, path: req.url,
        method: req.method,
        headers: { ...req.headers, host: `localhost:${HTTP_PORT}` },
    };
    const upstream = http.request(opts, upRes => {
        res.writeHead(upRes.statusCode, {
            ...upRes.headers,
            'Access-Control-Allow-Origin': '*',
        });
        upRes.pipe(res);
    });
    upstream.on('error', () => {
        res.writeHead(502);
        res.end(JSON.stringify({ error: 'sensing server offline', hint: `start: cd v2 && cargo run -p wifi-densepose-sensing-server -- --bind-addr 0.0.0.0 --allowed-host ${localIP()}` }));
    });
    req.pipe(upstream);
}

// Forward requests to an ESP32 node's OTA HTTP server (port 8032).
function proxyNode(req, res, nodeIp, nodePath) {
    // Validate IP is in the private range to prevent SSRF to public internet.
    const parts = nodeIp.split('.').map(Number);
    const isPrivate = (parts[0] === 10) ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168);
    if (!isPrivate) { res.writeHead(403); res.end('Only private IPs allowed'); return; }

    const opts = {
        hostname: nodeIp, port: 8032, path: nodePath + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''),
        method: req.method,
        headers: { ...req.headers, host: `${nodeIp}:8032` },
        timeout: 5000,
    };
    const upstream = http.request(opts, upRes => {
        res.writeHead(upRes.statusCode, {
            ...upRes.headers,
            'Access-Control-Allow-Origin': '*',
        });
        upRes.pipe(res);
    });
    upstream.on('error', () => {
        res.writeHead(502);
        res.end(JSON.stringify({ error: 'node unreachable', node: nodeIp, port: 8032 }));
    });
    req.pipe(upstream);
}

function onRequest(req, res) {
    let urlPath = decodeURIComponent(req.url.split('?')[0]);
    urlPath = path.posix.normalize(urlPath).replace(/^(\.\.\/)+/, '');

    // Proxy all /api/* and /health/* to the Rust sensing server
    if (urlPath.startsWith('/api/') || urlPath.startsWith('/health')) {
        return proxyApi(req, res);
    }

    // Proxy /node/<ip>/<path> → http://<ip>:8032/<path>  (ESP32 OTA/config server)
    // Avoids CORS: requests from the iPhone HTTPS page go through this server.
    const nodeMatch = urlPath.match(/^\/node\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/.*)?$/);
    if (nodeMatch) {
        const nodeIp   = nodeMatch[1];
        const nodePath = nodeMatch[2] || '/';
        return proxyNode(req, res, nodeIp, nodePath);
    }

    // Root → xray dashboard
    if (urlPath === '/' || urlPath === '') urlPath = '/xray.html';

    // Cert download
    if (urlPath === '/certs/ruview-local.crt') {
        return serveFile(res, CERT_FILE, CERTS_DIR);
    }

    serveFile(res, path.join(UI_DIR, urlPath), UI_DIR);
}

// ─── WebSocket TCP proxy ──────────────────────────────────────────────────────
// Tunnels HTTP Upgrade (WebSocket) connections to the Rust sensing server.
// No external npm packages needed — raw TCP pipe via net.Socket.
function onUpgrade(req, clientSocket, head) {
    if (!req.url.startsWith('/ws/')) { clientSocket.destroy(); return; }

    const upstream = net.connect(WS_PORT, WS_HOST);
    upstream.once('connect', () => {
        // Rewrite Host to localhost so the sensing server's DNS-rebinding guard accepts it.
        const rewritten = Object.entries(req.headers)
            .map(([k, v]) => k.toLowerCase() === 'host' ? `host: localhost:${WS_PORT}` : `${k}: ${v}`)
            .join('\r\n');
        upstream.write(`${req.method} ${req.url} HTTP/1.1\r\n${rewritten}\r\n\r\n`);
        if (head && head.length) upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
    });
    upstream.on('error', ()  => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
    clientSocket.on('end',   () => upstream.end());
}

// ─── QR-like URL printer ──────────────────────────────────────────────────────
function printBanner(ip) {
    const url = `https://${ip}:${PORT}`;
    const certUrl = `https://${ip}:${PORT}/certs/ruview-local.crt`;
    const line = '═'.repeat(60);
    console.log(`\n╔${line}╗`);
    console.log(`║  RuView X-Ray Dashboard — Local HTTPS Server${' '.repeat(14)}║`);
    console.log(`╠${line}╣`);
    console.log(`║  Dashboard:  ${url.padEnd(46)}║`);
    console.log(`║  WS proxy:   ${('wss://'+ip+':'+PORT+'/ws/sensing → :'+WS_PORT).padEnd(46)}║`);
    console.log(`╠${line}╣`);
    console.log(`║  ── iPhone setup (one-time) ──${' '.repeat(30)}║`);
    console.log(`║  1. In Safari open: ${certUrl.padEnd(39)}║`);
    console.log(`║  2. Tap "Allow" → Settings → General →${' '.repeat(21)}║`);
    console.log(`║     VPN & Device Management → Install cert${' '.repeat(18)}║`);
    console.log(`║  3. Settings → General → About →${' '.repeat(27)}║`);
    console.log(`║     Certificate Trust Settings → enable ruview.local${' '.repeat(8)}║`);
    console.log(`║  4. Open: ${url.padEnd(49)}║`);
    console.log(`╠${line}╣`);
    console.log(`║  Also start the sensing server:${' '.repeat(28)}║`);
    console.log(`║  cd v2 && cargo run -p wifi-densepose-sensing-server${' '.repeat(8)}║`);
    console.log(`║  -- --bind-addr 0.0.0.0 --allowed-host ${ip.padEnd(20)}║`);
    console.log(`╚${line}╝\n`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
const ip = localIP();

if (REGEN || !fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
    generateCert(ip);
} else {
    console.log('📜  Using existing certificate (pass --regen-cert to regenerate).');
}

const server = https.createServer(
    { cert: fs.readFileSync(CERT_FILE), key: fs.readFileSync(KEY_FILE) },
    onRequest
);
server.on('upgrade', onUpgrade);
server.listen(PORT, '0.0.0.0', () => printBanner(ip));

server.on('error', e => {
    if (e.code === 'EADDRINUSE') console.error(`\n❌  Port ${PORT} in use — pass --port <other> to change.\n`);
    else console.error('Server error:', e.message);
    process.exit(1);
});
