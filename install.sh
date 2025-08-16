
#!/usr/bin/env bash
set -euo pipefail
LE_STAGING=0
RECONFIGURE=0

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

COLOR() { tput setaf "$1"; }
RESET() { tput sgr0; }

ask() {
  local prompt="$1" default="${2:-}"
  read -rp "$(COLOR 6)${prompt}$( [ -n "$default" ] && printf " [%s]" "$default" ; )$(RESET) " REPLY
  echo "${REPLY:-$default}"
}

get_public_ipv4() {
  curl -4s https://api.ipify.org || curl -4s https://ifconfig.me
}

dns_a_record() {
  local host="$1"
  # Use 1.1.1.1 public resolver
  dig +short A "$host" @1.1.1.1 | head -n1
}

ensure_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "Installing Docker Compose plugin..."
    mkdir -p ~/.docker/cli-plugins
    curl -SL https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-x86_64 \
      -o ~/.docker/cli-plugins/docker-compose
    chmod +x ~/.docker/cli-plugins/docker-compose
  fi
}

purge() {
  echo "$(COLOR 1)Purging stack containers and volumes (certs preserved)...$(RESET)"
  docker compose down -v --remove-orphans || true
  rm -rf www || true
  echo "Done."
}

wipe_certs() {
  echo "$(COLOR 1)Wiping Let's Encrypt certificates...$(RESET)"
  rm -rf letsencrypt
  echo "Done."
}

usage() {
  cat <<EOF
Usage: $0 [--purge] [--wipe-certs] [--staging] [--reconfigure]

Without flags, runs an idempotent install/upgrade:
  - creates config/.env if missing
  - checks DNS A record points to this server
  - obtains/renews certs
  - builds/starts docker compose
EOF
}

for arg in "$@"; do
  case "$arg" in
    --purge) purge; exit 0 ;;
    --wipe-certs) wipe_certs; exit 0 ;;
    --staging) LE_STAGING=1 ;;
    --reconfigure|--ask-domain) RECONFIGURE=1 ;;
    --help) usage; exit 0 ;;
  esac
done

mkdir -p config letsencrypt www

DOMAIN_FILE="config/domain.txt"
EMAIL_FILE="config/email.txt"
SECRET_FILE="config/secret.txt"
CAPTURE_IP_FILE="config/capture_ip.txt"

DOMAIN="${DOMAIN:-$( [[ -f "$DOMAIN_FILE" ]] && cat "$DOMAIN_FILE" || echo "")}"
EMAIL="${EMAIL:-$( [[ -f "$EMAIL_FILE" ]] && cat "$EMAIL_FILE" || echo "")}"
SECRET="${SECRET:-$( [[ -f "$SECRET_FILE" ]] && cat "$SECRET_FILE" || echo "")}"
CAPTURE_IP="${CAPTURE_IP:-$( [[ -f "$CAPTURE_IP_FILE" ]] && cat "$CAPTURE_IP_FILE" || echo "")}"

[[ -z "$DOMAIN" ]] && DOMAIN="$(ask "Enter your DoH domain (e.g., dns.example.com):")"
[[ -z "$EMAIL"  ]] && EMAIL="$(ask "Enter your email for Let's Encrypt:" )"
[[ -z "$SECRET" ]] && SECRET="$(openssl rand -hex 16)"
[[ -z "$CAPTURE_IP" ]] && CAPTURE_IP="$(ask "IPv4 to return for all A queries (capture-all):" "$(get_public_ipv4)")"

echo "$DOMAIN"     > "$DOMAIN_FILE"
echo "$EMAIL"      > "$EMAIL_FILE"
echo "$SECRET"     > "$SECRET_FILE"
echo "$CAPTURE_IP" > "$CAPTURE_IP_FILE"

ensure_docker

PUBIP="$(get_public_ipv4)"
DNSIP="$(dns_a_record "$DOMAIN")"
echo "Public IPv4: $PUBIP"
echo "A $DOMAIN -> $DNSIP"
if [[ "$PUBIP" != "$DNSIP" ]]; then
  echo "$(COLOR 1)Domain DOES NOT point to this server. Fix DNS and re-run.$(RESET)"
  exit 1
fi

# Write config/config.json from example
cat > config/config.json <<JSON
{
  "host": "$DOMAIN",
  "admin_email": "$EMAIL",
  "auth": {
    "enabled": true,
    "scheme": "Bearer",
    "secret": "$SECRET",
    "allow_query_param": true,
    "query_param": "key"
  },
  "ipv6": { "disabled": true },
  "capture": {
    "capture_all_domains": true,
    "capture_ip": "$CAPTURE_IP",
    "ttl": 300
  },
  "overrides": {},
  "upstream_mode": "dns53",
  "dns53_upstreams": ["1.1.1.1", "8.8.8.8"],
  "upstreams": [
    { "name": "cloudflare", "url": "https://1.1.1.1/dns-query" },
    { "name": "google",     "url": "https://dns.google/dns-query" }
  ],
  "rate_limit": { "rps": 5, "burst": 20 },
  "cache": { "enabled": true, "max_entries": 5000, "min_ttl_seconds": 30, "max_ttl_seconds": 300 },
  "resolver": {
    "mode": "doh",
    "doh": [
      { "name": "cloudflare", "url": "https://1.1.1.1/dns-query" },
      { "name": "google",     "url": "https://dns.google/dns-query" }
    ],
    "udp": { "servers": ["1.1.1.1:53","8.8.8.8:53"] },
    "dot": [
      { "name": "cloudflare", "addr": "1.1.1.1:853", "servername": "cloudflare-dns.com" },
      { "name": "google",     "addr": "8.8.8.8:853", "servername": "dns.google" }
    ]
  },
  "resolver_mode": "doh",
  "udp": { "servers": ["1.1.1.1:53","8.8.8.8:53"] },
  "dot": [
    { "name": "cloudflare", "addr": "1.1.1.1:853", "servername": "cloudflare-dns.com" },
    { "name": "google",     "addr": "8.8.8.8:853", "servername": "dns.google" }
  ],
  "logging": { "json": true }
}
JSON

# Prepare nginx to serve correct host directory for certs
mkdir -p "letsencrypt/live/$DOMAIN"
# Obtain/renew certs (HTTP-01 via port 80 mapped to nginx)
if [ -f "letsencrypt/live/$DOMAIN/fullchain.pem" ] && [ -f "letsencrypt/live/$DOMAIN/privkey.pem" ]; then
  echo "Existing certificate for $DOMAIN found. Skipping issuance."
  docker compose up -d nginx
else
  echo "Issuing certificate via standalone certbot on :80..."
  docker rm -f doh-certbot-oneshot >/dev/null 2>&1 || true
  docker run --name doh-certbot-oneshot --rm -p 80:80 \
    -v "$PWD/letsencrypt:/etc/letsencrypt" \
    certbot/certbot:latest certonly --standalone --agree-tos -m "$EMAIL" \
    --cert-name "$DOMAIN" -d "$DOMAIN" --non-interactive --keep-until-expiring $( [ "$LE_STAGING" = "1" ] && printf -- "--staging" )
  echo "Starting nginx with issued certificate..."
  docker compose up -d nginx
fi

# Build and start app + watchtower
docker compose build doh
docker compose up -d doh watchtower

echo
echo "$(COLOR 2)Done!$(RESET)"
echo "Domain: $DOMAIN"
echo "Auth:   Authorization: Bearer $SECRET"
echo "DoH:    https://$DOMAIN/dns-query"
echo
echo "Reinstall: re-run ./install.sh (idempotent)"
echo "Purge:     ./install.sh --purge   (preserves certs)"
echo "WipeCerts: ./install.sh --wipe-certs"


# Render nginx.conf with the actual domain
sed -i "s/__DOMAIN__/$DOMAIN/g" nginx/nginx.conf
docker compose restart nginx || true

echo
echo "Firefox setup:"
echo "  about:config → network.trr.mode = 3"
echo "  about:config → network.trr.uri  = https://$DOMAIN/dns-query?key=$SECRET"
echo "  about:config → network.trr.bootstrapAddress = $(get_public_ipv4)"
