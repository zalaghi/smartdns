# DoH Gateway (IPv4‑only, auth‑gated) 

High‑performance **DNS‑over‑HTTPS** + **TCP SNI proxy** for geolocation routing. By default it **captures all A‑records** to your server’s IPv4 so client traffic goes through your gateway; TLS connections are transparently forwarded to the real origin using SNI.

> Version: **v5.6** (DoH by default; optional DoT/UDP upstreams)

---

## Table of contents
- [What this does](#what-this-does)
- [How geolocation routing works](#how-geolocation-routing-works)
- [Repo structure](#repo-structure)
- [Quick start](#quick-start)
- [Installer flags](#installer-flags)
- [Configuration](#configuration)
  - [Auth](#auth)
  - [IPv6](#ipv6)
  - [Capture (all or selective)](#capture-all-or-selective)
  - [Resolver upstream mode (DoH / DoT / UDP)](#resolver-upstream-mode-doh--dot--udp)
  - [Rate limit & cache](#rate-limit--cache)
  - [Logging](#logging)
- [Firefox setup (TRR/DoH)](#firefox-setup-trrdoh)
- [Verifying it works](#verifying-it-works)
- [Operations](#operations)
  - [Reinstall / purge / reconfigure](#reinstall--purge--reconfigure)
  - [Certificates & rate limits](#certificates--rate-limits)
  - [Blocking QUIC (optional)](#blocking-quic-optional)
  - [Upgrading images automatically](#upgrading-images-automatically)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)

---

## What this does
- **DoH server** (internal `:8080`, fronted by nginx TLS on `:8443`).
- **Shared‑secret auth** for DoH: default via `Authorization: Bearer <secret>`, optional `?key=` for browsers/clients that cannot set headers.
- **Capture‑all mode** ON by default: every A‑record returns your gateway IPv4. (Selective overrides also supported.)
- **TCP SNI proxy** on `:443`: reads ClientHello SNI and transparently forwards TCP to `<sni>:443`. If SNI equals your DoH host, it routes to local nginx `:8443`.
- **IPv6 disabled**: AAAA queries return empty; proxy dials IPv4 only.
- **Flexible upstreams**: DoH (default), or DoT/UDP as you choose.
- **Dockerized** with `watchtower` for unattended updates.

> **Why TCP only?** QUIC/HTTP3 (UDP/443) can bypass a TCP SNI proxy. You can block UDP/443 at the server to force TCP—see [Blocking QUIC](#blocking-quic-optional).

---

## How geolocation routing works
1. Client resolves `example.com` via your **DoH** → gets **your server’s IPv4** (capture‑all or override).
2. Client connects to your server `:443`; the **SNI proxy** peeks the SNI and forwards the TCP stream to the real origin `example.com:443`.
3. The origin sees the connection coming **from your server’s IP/region**, bypassing client geolocation restrictions.

---

## Repo structure
```
.
├─ docker-compose.yml        # doh app, nginx (TLS), watchtower
├─ Dockerfile                # multi-stage build for Go app
├─ main.go                   # DoH server + SNI TCP proxy
├─ nginx/
│  └─ nginx.conf            # container nginx (TLS on 8443)
├─ config/
│  └─ config.example.json   # template config
├─ install.sh                # idempotent installer (certs, compose)
└─ README.md
```

---

## Quick start
> Requirements: A domain pointing to your server’s IPv4 (A record), ports **80/443/8443** reachable.

```bash
# on your server
git clone <this repo>
cd <repo>
./install.sh
```
The installer will:
1) Ask for **domain** and **email** (pre-fills from last run if present).
2) Verify your domain’s **A record** equals the server’s public IPv4.
3) Obtain a Let’s Encrypt certificate (skips if one already exists).
4) Start nginx (TLS on 8443), build & start the `doh` app (SNI proxy on 443), and `watchtower`.

**Default DoH endpoint:** `https://<your-domain>/dns-query`  
**Default auth:** header `Authorization: Bearer <secret>` **or** query `?key=<secret>` (query allowed by default).

---

## Installer flags
```bash
./install.sh --staging       # use LE staging (good for testing; untrusted cert)
./install.sh --reconfigure   # force prompts for domain/email again
./install.sh --purge         # stop & remove containers/volumes (keeps certs)
./install.sh --wipe-certs    # delete Let's Encrypt certs
```
The installer is **idempotent**—safe to run multiple times.

---

## Configuration
Your runtime config lives at `config/config.json`.

**Full example:**
```jsonc
{
  "host": "dns.example.com",
  "admin_email": "you@example.com",

  "auth": {
    "enabled": true,
    "scheme": "Bearer",
    "secret": "CHANGE_ME",
    "allow_query_param": true,         // allow ?key=... for browsers
    "query_param": "key"
  },

  "ipv6": { "disabled": true },      // AAAA stripped; proxy is IPv4-only

  "capture": {
    "capture_all_domains": true,       // A records all point to capture_ip
    "capture_ip": "203.0.113.10",    // your server’s IPv4
    "ttl": 300
  },

  "overrides": {
    // substring match → IP, only used when capture_all_domains=false
    "youtube": "203.0.113.10"
  },

  // Legacy DoH upstream list (used when resolver_mode = "doh")
  "upstreams": [
    { "name": "cloudflare", "url": "https://1.1.1.1/dns-query" },
    { "name": "google",     "url": "https://dns.google/dns-query" }
  ],

  // NEW: choose upstream mode (doh | udp | dot)
  "resolver_mode": "doh",

  // UDP/53 upstream servers (used when resolver_mode = "udp")
  "udp": { "servers": ["1.1.1.1:53", "8.8.8.8:53"] },

  // DoT/853 upstream servers (used when resolver_mode = "dot")
  "dot": [
    { "name": "cloudflare", "addr": "1.1.1.1:853", "servername": "cloudflare-dns.com" },
    { "name": "google",     "addr": "8.8.8.8:853", "servername": "dns.google" }
  ],

  "rate_limit": { "rps": 5, "burst": 20 },

  "cache": {
    "enabled": true,
    "max_entries": 5000,
    "min_ttl_seconds": 30,
    "max_ttl_seconds": 300
  },

  "logging": { "json": true }
}
```

### Auth
- **Header (recommended)**: `Authorization: Bearer <secret>`
- **Query** (for browsers): `?key=<secret>` (enabled by default)

### IPv6
- If `ipv6.disabled = true`: AAAA queries return empty; proxy dials `tcp4` only. Useful to avoid IPv6 leaks when geofencing.

### Capture (all or selective)
- **All domains**: set `capture.capture_all_domains = true` and `capture_ip` to your server’s IPv4 (default).
- **Selective only**: set `capture_all_domains = false` and list substrings under `overrides` (e.g., `"netflix": "<IP>"`). Only A‑queries are rewritten.

### Resolver upstream mode (DoH / DoT / UDP)
Pick the upstream transport used when your server forwards queries you don’t rewrite:
- `resolver_mode = "doh"` (default): uses `upstreams[].url` (HTTPS, HTTP/2 keep‑alive)
- `resolver_mode = "udp"`: uses `udp.servers` (e.g., `1.1.1.1:53`, `8.8.8.8:53`)
- `resolver_mode = "dot"`: uses `dot[]` (TLS 1.2+, SNI enforced)

> You can change `resolver_mode` and restart the `doh` container.

### Rate limit & cache
- Simple per‑IP token bucket (`rps`, `burst`).
- In‑memory LRU‑ish cache with TTL clamping (`min_ttl_seconds`/`max_ttl_seconds`).

### Logging
- JSON logs if `logging.json = true`.
- Nginx shows `/dns-query` hits; the Go app logs startup and errors.

---

## Firefox setup (TRR/DoH)
1. Open `about:config`
2. Set:
   - `network.trr.mode = 3` (DoH only; use `2` for fallback)
   - `network.trr.uri = https://<your-domain>/dns-query?key=<secret>`
   - `network.trr.bootstrapAddress = <your server IPv4>`
3. Optional (to force TCP path through the proxy while testing):
   - `network.dns.disableIPv6 = true`
   - `network.http.http3.enabled = false`

---

## Verifying it works
**DoH request (header):**
```bash
curl -s --http2 -H 'Content-Type: application/dns-message'   -H 'Accept: application/dns-message'   -H 'Authorization: Bearer <secret>'   --data-binary @query.bin https://<your-domain>/dns-query | hexdump -C | head
```

**DoH request (query param):**
```bash
curl -s --http2 -H 'Content-Type: application/dns-message'   -H 'Accept: application/dns-message'   --data-binary @query.bin   'https://<your-domain>/dns-query?key=<secret>' | hexdump -C | head
```

**SNI proxy path (proof):**
```bash
curl --http1.1 --resolve example.com:443:<YOUR_SERVER_IP> https://example.com/ -I
```
You should receive headers from `example.com`, showing the proxy is forwarding correctly.

---

## Operations
### Reinstall / purge / reconfigure
- Re‑run `./install.sh` anytime (idempotent).
- `./install.sh --reconfigure` → re‑ask domain/email.
- `./install.sh --purge` → stop & remove containers/volumes (keeps certs).
- `./install.sh --wipe-certs` → delete certs (use with care).

### Certificates & rate limits
- Installer **skips issuance** if `letsencrypt/live/<domain>/` already has a valid cert.
- When issuing, uses a stable `--cert-name <domain>` so it **reuses** the lineage.
- Use `--staging` to test without hitting production rate limits.

### Blocking QUIC (optional)
To ensure traffic takes the TCP SNI path:
```bash
sudo iptables -A INPUT -p udp --dport 443 -j REJECT
```

### Upgrading images automatically
`watchtower` runs with label filtering to update only this stack’s images. It will restart containers when new tags are available.

---

## Troubleshooting
- **Browser still shows your own IP** on check sites:
  - Ensure Firefox TRR is enabled (`mode=3`, correct `uri`, `bootstrapAddress`).
  - Temporarily set `network.http.http3.enabled=false` and `network.dns.disableIPv6=true` to avoid QUIC/IPv6 leaks.
  - Confirm your DoH is hit: `docker logs doh-nginx | grep /dns-query`.
- **Let’s Encrypt rate limit** during install:
  - Use `--staging` for testing; or wait until your window resets; or reuse existing certs (installer skips if present).
- **DoT/UDP resolver not used**:
  - Check `resolver_mode` and restart the `doh` container after changes.
- **Build errors**:
  - Always rebuild the app after pulling changes: `docker compose build doh --no-cache`.

---

## Security notes
- Prefer **header auth**; use `?key=` for browsers only. Rotate secrets periodically.
- Keep capture‑all enabled only if you intend to route *all* traffic via your gateway. Otherwise, use selective `overrides`.
- The SNI proxy is a **raw TCP passthrough**—it does not terminate TLS for foreign domains and only routes based on SNI.
- Don’t expose internal port `:8080`; only nginx should reach it.

---

**License**: MIT (or your choice)

**Contributions**: PRs welcome. Please include error logs and your `config.json` (with secrets redacted) when reporting issues.
