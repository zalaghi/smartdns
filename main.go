package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/tls"

	"github.com/miekg/dns"
)

// ====================== Config ======================

type Config struct {
	Host           string            `json:"host"`
	UpstreamMode   string            `json:"upstream_mode"`
	Dns53Upstreams []string          `json:"dns53_upstreams"`
	AdminEmail     string            `json:"admin_email"`
	Auth           AuthConfig        `json:"auth"`
	IPv6           IPv6Config        `json:"ipv6"`
	Capture        CaptureConfig     `json:"capture"`
	Overrides      map[string]string `json:"overrides"`
	Upstreams      []Upstream        `json:"upstreams"`
	RateLimit      RateLimit         `json:"rate_limit"`
	Cache          CacheConfig       `json:"cache"`
	Logging        LoggingConfig     `json:"logging"`

	// ResolverMode selects how we resolve queries not answered from cache/overrides.
	// "udp" -> use UDP/53 servers, "dot" -> DNS over TLS. Any other value
	// falls back to the legacy DoH/DNS53 logic governed by UpstreamMode.
	ResolverMode string `json:"resolver_mode"`
	UDP          struct {
		// Servers to query when ResolverMode = "udp"
		Servers []string `json:"servers"` // e.g., ["1.1.1.1:53","8.8.8.8:53"]
	} `json:"udp"`
	// DoT upstreams used when ResolverMode = "dot"
	DoT []struct {
		Name       string `json:"name"`
		Addr       string `json:"addr"`       // "1.1.1.1:853"
		ServerName string `json:"servername"` // "cloudflare-dns.com"
	} `json:"dot"`
}

type AuthConfig struct {
	Enabled         bool   `json:"enabled"`
	Scheme          string `json:"scheme"` // e.g. "Bearer"
	Secret          string `json:"secret"`
	AllowQueryParam bool   `json:"allow_query_param"`
	QueryParam      string `json:"query_param"`
}

type DoTUpstream struct {
	Name       string `json:"name"`
	Addr       string `json:"addr"`
	ServerName string `json:"servername"`
}

type IPv6Config struct {
	Disabled bool `json:"disabled"`
}

type CaptureConfig struct {
	CaptureAll bool   `json:"capture_all_domains"`
	CaptureIP  string `json:"capture_ip"`
	TTL        uint32 `json:"ttl"`
}

type Upstream struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type RateLimit struct {
	RPS   int `json:"rps"`
	Burst int `json:"burst"`
}

type CacheConfig struct {
	Enabled       bool  `json:"enabled"`
	MaxEntries    int   `json:"max_entries"`
	MinTTLSeconds int64 `json:"min_ttl_seconds"`
	MaxTTLSeconds int64 `json:"max_ttl_seconds"`
}

type LoggingConfig struct {
	// JSON enables structured JSON logging instead of the default text format.
	JSON bool `json:"json"`
}

// ====================== Globals ======================

var (
	cfg        Config
	httpClient *http.Client
	rrCounter  uint64
	cache      *dnsCache
	limiter    *ipLimiter
)

// ====================== Utilities ======================

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func nowUnix() int64 { return time.Now().Unix() }

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// jsonLogWriter writes log lines as JSON objects with time and msg fields.
type jsonLogWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newJSONLogWriter(w io.Writer) *jsonLogWriter {
	return &jsonLogWriter{enc: json.NewEncoder(w)}
}

func (w *jsonLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry := map[string]string{
		"time": time.Now().Format(time.RFC3339),
		"msg":  strings.TrimSpace(string(p)),
	}
	if err := w.enc.Encode(entry); err != nil {
		return 0, err
	}
	return len(p), nil
}

// getClientIP extracts the real client IP considering proxy headers set by nginx.
func getClientIP(r *http.Request) string {
	// X-Forwarded-For may contain a list; take the first (original client)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// ====================== Simple LRU-ish Cache ======================

type cacheEntry struct {
	key  string
	data []byte
	exp  int64
}

type dnsCache struct {
	mu    sync.Mutex
	data  map[string]*cacheEntry
	order []string
	max   int
}

func newDNSCache(max int) *dnsCache {
	return &dnsCache{data: make(map[string]*cacheEntry, max), order: make([]string, 0, max), max: max}
}

func cacheKey(msg *dns.Msg) string {
	if len(msg.Question) == 0 {
		return ""
	}
	q := msg.Question[0]
	return strings.ToLower(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + strconv.Itoa(btoi(msg.RecursionDesired))
}

func (c *dnsCache) get(k string) ([]byte, bool) {
	if k == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data[k]
	if !ok || e.exp < nowUnix() {
		if ok {
			delete(c.data, k)
		}
		return nil, false
	}
	return e.data, true
}

func (c *dnsCache) set(k string, data []byte, ttl int64) {
	if k == "" || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// evict if needed
	if len(c.data) >= c.max && c.max > 0 {
		// remove oldest
		oldk := c.order[0]
		c.order = c.order[1:]
		delete(c.data, oldk)
	}
	c.data[k] = &cacheEntry{key: k, data: data, exp: nowUnix() + ttl}
	c.order = append(c.order, k)
}

// ====================== IP Rate Limiter (very simple) ======================

type tokenBucket struct {
	tokens int
	max    int
	last   time.Time
	rps    int
}

func (tb *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(tb.last).Seconds()
	tb.last = now
	tb.tokens += int(elapsed * float64(tb.rps))
	if tb.tokens > tb.max {
		tb.tokens = tb.max
	}
	if tb.tokens <= 0 {
		return false
	}
	tb.tokens--
	return true
}

type ipLimiter struct {
	mu    sync.Mutex
	rps   int
	burst int
	m     map[string]*tokenBucket
}

func newIPLimiter(rps, burst int) *ipLimiter {
	return &ipLimiter{rps: rps, burst: burst, m: make(map[string]*tokenBucket)}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	tb, ok := l.m[ip]
	if !ok {
		tb = &tokenBucket{tokens: l.burst, max: l.burst, last: time.Now(), rps: l.rps}
		l.m[ip] = tb
	}
	return tb.allow()
}

// ====================== Upstream Selection ======================

func pickUpstreamDoH() string {
	if len(cfg.Upstreams) == 0 {
		return "https://1.1.1.1/dns-query"
	}
	idx := atomic.AddUint64(&rrCounter, 1)
	return cfg.Upstreams[int(idx)%len(cfg.Upstreams)].URL
}

// ====================== DoH Handler ======================

func dohHandler(w http.ResponseWriter, r *http.Request) {
	cl := getClientIP(r)
	if limiter != nil && !limiter.allow(cl) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	// Auth
	if cfg.Auth.Enabled {
		ok := false
		authz := r.Header.Get("Authorization")
		if authz != "" && strings.HasPrefix(strings.ToLower(authz), strings.ToLower(cfg.Auth.Scheme)+" ") {
			token := strings.TrimSpace(authz[len(cfg.Auth.Scheme)+1:])
			ok = (token == cfg.Auth.Secret)
		}
		if !ok && cfg.Auth.AllowQueryParam && cfg.Auth.QueryParam != "" {
			if qp := r.URL.Query().Get(cfg.Auth.QueryParam); qp != "" && qp == cfg.Auth.Secret {
				ok = true
			}
		}
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var payload []byte
	switch r.Method {
	case "GET":
		param := r.URL.Query().Get("dns")
		if param == "" {
			http.Error(w, "missing dns param", http.StatusBadRequest)
			return
		}
		b, err := base64.RawURLEncoding.DecodeString(param)
		if err != nil {
			http.Error(w, "bad dns b64", http.StatusBadRequest)
			return
		}
		payload = b
	case "POST":
		b, err := io.ReadAll(r.Body)
		if err != nil || len(b) == 0 {
			http.Error(w, "empty body", http.StatusBadRequest)
			return
		}
		payload = b
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(payload); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}
	if len(req.Question) == 0 {
		http.Error(w, "no question", http.StatusBadRequest)
		return
	}
	q := req.Question[0]

	// IPv6 disabled -> respond NOERROR/empty for AAAA
	if cfg.IPv6.Disabled && q.Qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Rcode = dns.RcodeSuccess
		wire, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
		return
	}

	// Cache
	key := ""
	if cache != nil {
		key = cacheKey(req)
		if data, ok := cache.get(key); ok {
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(data)
			return
		}
	}

	// Capture-all or overrides for A queries
	if q.Qtype == dns.TypeA {
		nameLC := strings.ToLower(strings.TrimSuffix(q.Name, "."))

		if cfg.Capture.CaptureAll && cfg.Capture.CaptureIP != "" {
			respWire, err := answerA(req, cfg.Capture.CaptureIP, cfg.Capture.TTL)
			if err == nil {
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(respWire)
				if cache != nil {
					ttl := clampTTL(int64(cfg.Capture.TTL), cfg.Cache.MinTTLSeconds, cfg.Cache.MaxTTLSeconds)
					cache.set(key, respWire, ttl)
				}
				return
			}
		}
		// substring override
		for sub, ip := range cfg.Overrides {
			if strings.Contains(nameLC, strings.ToLower(sub)) {
				respWire, err := answerA(req, ip, cfg.Capture.TTL)
				if err == nil {
					w.Header().Set("Content-Type", "application/dns-message")
					w.Write(respWire)
					if cache != nil {
						ttl := clampTTL(int64(cfg.Capture.TTL), cfg.Cache.MinTTLSeconds, cfg.Cache.MaxTTLSeconds)
						cache.set(key, respWire, ttl)
					}
					return
				}
			}
		}
	}

	// Resolve upstream depending on ResolverMode
	var body []byte
	var ferr error
	switch strings.ToLower(strings.TrimSpace(cfg.ResolverMode)) {
	case "udp":
		var resp *dns.Msg
		resp, ferr = resolveViaUDP(req)
		if ferr == nil {
			body, ferr = resp.Pack()
		}
	case "dot":
		var resp *dns.Msg
		resp, ferr = resolveViaDoT(req)
		if ferr == nil {
			body, ferr = resp.Pack()
		}
	default:
		if strings.ToLower(strings.TrimSpace(cfg.UpstreamMode)) == "dns53" {
			body, ferr = forwardDNS53(r.Context(), payload)
		} else {
			up := pickUpstreamDoH()
			upReq, err := http.NewRequestWithContext(r.Context(), "POST", up, bytes.NewReader(payload))
			if err != nil {
				http.Error(w, "upstream error", http.StatusBadGateway)
				return
			}
			upReq.Header.Set("Content-Type", "application/dns-message")
			upReq.Header.Set("Accept", "application/dns-message")
			resp, err := httpClient.Do(upReq)
			if err != nil {
				http.Error(w, "upstream unreachable", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				http.Error(w, fmt.Sprintf("upstream status %d", resp.StatusCode), http.StatusBadGateway)
				return
			}
			body, _ = io.ReadAll(resp.Body)
		}
	}
	if ferr != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}

	// clamp TTLs if caching enabled
	if cache != nil {
		msg := new(dns.Msg)
		if err := msg.Unpack(body); err == nil {
			ttl := extractMinTTL(msg)
			ttl = clampTTL(ttl, cfg.Cache.MinTTLSeconds, cfg.Cache.MaxTTLSeconds)
			if ttl > 0 {
				cache.set(key, body, ttl)
			}
		}
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(body)
}

func answerA(req *dns.Msg, ip string, ttl uint32) ([]byte, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	hdr := dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
	rr := &dns.A{Hdr: hdr, A: net.ParseIP(ip)}
	if rr.A == nil {
		return nil, errors.New("invalid ip for A")
	}
	resp.Answer = append(resp.Answer, rr)
	return resp.Pack()
}

func extractMinTTL(m *dns.Msg) int64 {
	min := int64(0)
	for _, rr := range append(append([]dns.RR{}, m.Answer...), append(m.Ns, m.Extra...)...) {
		if rr.Header().Ttl > 0 {
			if min == 0 || int64(rr.Header().Ttl) < min {
				min = int64(rr.Header().Ttl)
			}
		}
	}
	if min == 0 {
		min = 60
	}
	return min
}

func clampTTL(ttl, min, max int64) int64 {
	if min > 0 && ttl < min {
		ttl = min
	}
	if max > 0 && ttl > max {
		ttl = max
	}
	return ttl
}

// ====================== DNS53 Upstreams ======================

func pickUpstreamDNS53() string {
	if len(cfg.Dns53Upstreams) == 0 {
		return "1.1.1.1"
	}
	idx := atomic.AddUint64(&rrCounter, 1)
	return cfg.Dns53Upstreams[int(idx)%len(cfg.Dns53Upstreams)]
}

// forwardDNS53 sends the wire-format DNS message over UDP/53 (IPv4), with TCP fallback on truncation/error.
func forwardDNS53(ctx context.Context, wire []byte) ([]byte, error) {
	cUdp := &dns.Client{Net: "udp4", Timeout: 4 * time.Second}
	cTcp := &dns.Client{Net: "tcp4", Timeout: 6 * time.Second}
	server := net.JoinHostPort(pickUpstreamDNS53(), "53")

	// Try UDP first
	in, rtt, err := cUdp.ExchangeContext(ctx, &dns.Msg{}, server)
	_ = rtt
	// We can't use ExchangeContext directly with wire bytes; parse req then exchange
	req := new(dns.Msg)
	if err2 := req.Unpack(wire); err2 != nil {
		return nil, err2
	}
	in, rtt, err = cUdp.ExchangeContext(ctx, req, server)
	_ = rtt
	if err == nil && in != nil && !in.Truncated {
		return in.Pack()
	}
	// Fallback to TCP
	in, rtt, err = cTcp.ExchangeContext(ctx, req, server)
	_ = rtt
	if err != nil {
		return nil, err
	}
	return in.Pack()
}

// ====================== SNI Proxy ======================

// We accept raw TCP on :443, parse ClientHello to get SNI, then proxy TCP to either:
// - nginx:8443 if SNI == cfg.Host
// - <sni>:443 otherwise (IPv4 only dial)
func startSNIProxy() error {
	ln, err := net.Listen("tcp4", ":443")
	if err != nil {
		return err
	}
	log.Printf("SNI proxy listening on :443 (host: %s)", cfg.Host)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSNIConn(conn)
	}
}

func handleSNIConn(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	clientHello, peeked, err := readClientHello(c)
	if err != nil {
		return
	}
	server := ""
	host := strings.ToLower(clientHello.ServerName)
	if host == "" {
		// no SNI -> drop
		return
	}
	if equalHost(host, cfg.Host) {
		server = "nginx:8443"
	} else {
		server = net.JoinHostPort(host, "443")
	}
	up, err := net.DialTimeout("tcp4", server, 7*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	_ = c.SetDeadline(time.Time{})
	_ = up.SetDeadline(time.Time{})

	// Send peeked bytes to upstream, then pipe both ways
	if _, err := up.Write(peeked); err != nil {
		return
	}
	errc := make(chan struct{}, 2)
	go proxyCopy(up, c, errc)
	go proxyCopy(c, up, errc)
	<-errc
}

func proxyCopy(dst io.WriteCloser, src io.ReadCloser, done chan struct{}) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
	done <- struct{}{}
}

func equalHost(a, b string) bool {
	return strings.TrimSuffix(strings.ToLower(a), ".") == strings.TrimSuffix(strings.ToLower(b), ".")
}

// Minimal ClientHello parser to extract SNI and retain bytes
func readClientHello(r net.Conn) (*clientHelloInfo, []byte, error) {
	var buf bytes.Buffer

	// Read TLS record header
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, nil, err
	}
	buf.Write(hdr)
	if hdr[0] != 0x16 { // handshake
		return nil, nil, errors.New("not a handshake record")
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, recLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	buf.Write(body)
	if len(body) < 42 || body[0] != 0x01 { // ClientHello
		return nil, nil, errors.New("not a clienthello")
	}

	// Skip: msg len (3), version (2), random (32)
	p := 1 + 3 + 2 + 32
	if p+1 > len(body) {
		return nil, nil, errors.New("bad ch len")
	}
	sessionLen := int(body[p])
	p++
	p += sessionLen
	if p+2 > len(body) {
		return nil, nil, errors.New("bad cipher len")
	}
	cipherLen := int(body[p])<<8 | int(body[p+1])
	p += 2 + cipherLen
	if p+1 > len(body) {
		return nil, nil, errors.New("bad comp len")
	}
	compLen := int(body[p])
	p++
	p += compLen
	if p+2 > len(body) {
		return nil, nil, errors.New("no extensions")
	}
	extLen := int(body[p])<<8 | int(body[p+1])
	p += 2
	if p+extLen > len(body) {
		return nil, nil, errors.New("bad ext len")
	}
	end := p + extLen

	var sni string
	for p < end {
		if p+4 > len(body) {
			break
		}
		typ := int(body[p])<<8 | int(body[p+1])
		p += 2
		l := int(body[p])<<8 | int(body[p+1])
		p += 2
		if p+l > len(body) {
			break
		}
		if typ == 0 { // server_name
			// list len (2), name type (1), name len (2), name (n)
			q := p
			if q+5 > p+l {
				break
			}
			_ = int(body[q])<<8 | int(body[q+1])
			q += 2
			_ = int(body[q])
			q++
			nameLen := int(body[q])<<8 | int(body[q+1])
			q += 2
			if q+nameLen <= p+l {
				sni = string(body[q : q+nameLen])
			}
			break
		}
		p += l
	}
	if sni == "" {
		return nil, buf.Bytes(), errors.New("no sni")
	}
	return &clientHelloInfo{ServerName: sni}, buf.Bytes(), nil
}

type clientHelloInfo struct {
	ServerName string
}

// ====================== Boot ======================

func main() {
	path := envOr("CONFIG_PATH", "/config/config.json")
	b, err := os.ReadFile(path)
	must(err)
	must(json.Unmarshal(b, &cfg))

	// Set defaults
	if cfg.Capture.TTL == 0 {
		cfg.Capture.TTL = 300
	}
	if strings.TrimSpace(cfg.UpstreamMode) == "" {
		cfg.UpstreamMode = "dns53"
	}
	if strings.ToLower(cfg.UpstreamMode) == "dns53" && len(cfg.Dns53Upstreams) == 0 {
		cfg.Dns53Upstreams = []string{"1.1.1.1", "8.8.8.8"}
	}
	if cfg.RateLimit.RPS <= 0 {
		cfg.RateLimit.RPS = 5
	}
	if cfg.RateLimit.Burst <= 0 {
		cfg.RateLimit.Burst = 20
	}
	if cfg.Auth.Scheme == "" {
		cfg.Auth.Scheme = "Bearer"
	}

	if cfg.Logging.JSON {
		log.SetFlags(0)
		log.SetOutput(newJSONLogWriter(os.Stderr))
	}

	// HTTP client for DoH upstreams
	tr := &http.Transport{
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// IPv4 only
			d := net.Dialer{Timeout: 7 * time.Second}
			return d.DialContext(ctx, "tcp4", addr)
		},
	}
	httpClient = &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	// cache & limiter
	if cfg.Cache.Enabled && cfg.Cache.MaxEntries > 0 {
		cache = newDNSCache(cfg.Cache.MaxEntries)
	}
	limiter = newIPLimiter(cfg.RateLimit.RPS, cfg.RateLimit.Burst)

	// Start DoH over internal HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dohHandler)
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		log.Printf("DoH listening on :8080 (auth:%v, capture_all:%v, upstreams:%d)", cfg.Auth.Enabled, cfg.Capture.CaptureAll, len(cfg.Upstreams))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	// Start SNI proxy on :443
	must(startSNIProxy())
}

// ====================== Upstream resolvers ======================

func resolveViaUDP(req *dns.Msg) (*dns.Msg, error) {
	servers := cfg.UDP.Servers
	if len(servers) == 0 {
		servers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	for _, s := range servers {
		in, _, err := c.Exchange(req, s)
		if err == nil && in != nil {
			return in, nil
		}
	}
	return nil, errors.New("udp upstreams failed")
}

func resolveViaDoT(req *dns.Msg) (*dns.Msg, error) {
	up := cfg.DoT
	if len(up) == 0 {
		up = []struct {
			Name       string `json:"name"`
			Addr       string `json:"addr"`
			ServerName string `json:"servername"`
		}{
			{Name: "cloudflare", Addr: "1.1.1.1:853", ServerName: "cloudflare-dns.com"},
			{Name: "google", Addr: "8.8.8.8:853", ServerName: "dns.google"},
		}
	}
	for _, u := range up {
		c := &dns.Client{Net: "tcp-tls", Timeout: 7 * time.Second, TLSConfig: &tls.Config{ServerName: u.ServerName, MinVersion: tls.VersionTLS12}}
		in, _, err := c.Exchange(req, u.Addr)
		if err == nil && in != nil {
			return in, nil
		}
	}
	return nil, errors.New("dot upstreams failed")
}
