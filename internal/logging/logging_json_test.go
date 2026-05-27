// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT
package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// readJSONLines decodes each newline-delimited JSON object in buf into a
// slice of maps. Lines that fail to parse are silently skipped.
func readJSONLines(buf *bytes.Buffer) []map[string]interface{} {
	var out []map[string]interface{}
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

// jsonLogger returns a Logger writing JSON to buf (synchronous mode for tests).
func jsonLogger(buf *bytes.Buffer) *Logger {
	return NewWriterLogger(buf, Config{StdoutMode: "json", Synchronous: true}, "testmod")
}

// textLogger returns a Logger writing plain text to buf at info level (synchronous mode for tests).
func textLogger(buf *bytes.Buffer) *Logger {
	return NewWriterLogger(buf, Config{StdoutMode: "info", Synchronous: true}, "testmod")
}

// assertJSONString is a helper that asserts a string value in a JSON map.
func assertJSONString(t *testing.T, m map[string]interface{}, key, want string) {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Errorf("expected %q=%q, but field is missing or not a string (got %T: %v)", key, want, m[key], m[key])
		return
	}
	if v != want {
		t.Errorf("expected %q=%q, got %q", key, want, v)
	}
}

// dnsSubmap extracts the "dns" sub-object from a top-level event map.
func dnsSubmap(t *testing.T, obj map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, ok := obj["dns"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected 'dns' field to be a JSON object, got %T: %v", obj["dns"], obj["dns"])
	}
	return raw
}

// ---------------------------------------------------------------------------
// parseOutputMode
// ---------------------------------------------------------------------------

func TestParseOutputMode(t *testing.T) {
	cases := []struct {
		input       string
		wantJSON    bool
		wantEnabled bool
		wantLevel   Level
	}{
		{"json", true, true, LevelInfo},
		{"JSON", true, true, LevelInfo},
		{"debug", false, true, LevelDebug},
		{"info", false, true, LevelInfo},
		{"", false, true, LevelInfo},
		{"warn", false, true, LevelWarn},
		{"warning", false, true, LevelWarn},
		{"error", false, true, LevelError},
		{"off", false, false, LevelDebug},
		{"OFF", false, false, LevelDebug},
		{"unknown", false, true, LevelInfo},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			gotJSON, gotLvl, gotEnabled := parseOutputMode(tc.input)
			if gotJSON != tc.wantJSON {
				t.Errorf("isJSON: got %v, want %v", gotJSON, tc.wantJSON)
			}
			if gotEnabled != tc.wantEnabled {
				t.Errorf("enabled: got %v, want %v", gotEnabled, tc.wantEnabled)
			}
			if gotEnabled && gotLvl != tc.wantLevel {
				t.Errorf("level: got %v, want %v", gotLvl, tc.wantLevel)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// JSON general event
// ---------------------------------------------------------------------------

func TestJSONLogger_GeneralEvent(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	l.Infof("hello %s", "world")

	lines := readJSONLines(&buf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 JSON line, got %d:\n%s", len(lines), buf.String())
	}
	obj := lines[0]
	assertJSONString(t, obj, "level", "INFO")
	assertJSONString(t, obj, "type", TypeGeneral)
	assertJSONString(t, obj, "message", "hello world")
	assertJSONString(t, obj, "module", "testmod")
	if obj["timestamp"] == nil || obj["timestamp"] == "" {
		t.Error("expected non-empty timestamp")
	}
	if _, hasDNS := obj["dns"]; hasDNS {
		t.Error("general event must not have a 'dns' field")
	}
}

// ---------------------------------------------------------------------------
// Level filtering
// ---------------------------------------------------------------------------

func TestJSONLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)
	l.SetLevel(LevelWarn)

	l.Debugf("should not appear")
	l.Infof("also hidden")
	l.Warnf("visible warn")
	l.Errorf("visible error")

	lines := readJSONLines(&buf)
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines (warn+error), got %d:\n%s", len(lines), buf.String())
	}
	assertJSONString(t, lines[0], "level", "WARN")
	assertJSONString(t, lines[1], "level", "ERROR")
}

func TestJSONLogger_AllLevels(t *testing.T) {
	levels := []struct {
		emit func(*Logger)
		want string
	}{
		{func(l *Logger) { l.Debugf("d") }, "DEBUG"},
		{func(l *Logger) { l.Infof("i") }, "INFO"},
		{func(l *Logger) { l.Warnf("w") }, "WARN"},
		{func(l *Logger) { l.Errorf("e") }, "ERROR"},
	}
	for _, tc := range levels {
		var buf bytes.Buffer
		l := jsonLogger(&buf)
		l.SetLevel(LevelDebug)
		tc.emit(l)
		lines := readJSONLines(&buf)
		if len(lines) != 1 {
			t.Errorf("level %s: expected 1 line, got %d", tc.want, len(lines))
			continue
		}
		assertJSONString(t, lines[0], "level", tc.want)
	}
}

// ---------------------------------------------------------------------------
// Text mode must NOT emit JSON
// ---------------------------------------------------------------------------

func TestJSONLogger_TextModeNotJSON(t *testing.T) {
	var buf bytes.Buffer
	l := textLogger(&buf)
	l.Infof("plain text line")

	out := buf.String()
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("text-mode logger should not emit JSON, got: %s", out)
	}
	if !strings.Contains(out, "INFO") {
		t.Errorf("text-mode logger should contain INFO, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// "off" mode produces no output
// ---------------------------------------------------------------------------

func TestJSONLogger_OffMode(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "off"}, "t")
	l.Infof("should not appear")
	l.Warnf("also hidden")
	if buf.Len() > 0 {
		t.Errorf("off mode must produce no output, got: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// Per-output text-level filtering
// ---------------------------------------------------------------------------

func TestJSONLogger_WarnModeFiltersInfo(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "warn", Synchronous: true}, "t")
	l.Infof("hidden info")
	l.Warnf("visible warn")

	out := buf.String()
	if strings.Contains(out, "hidden info") {
		t.Error("INFO message must be filtered when mode=warn")
	}
	if !strings.Contains(out, "visible warn") {
		t.Error("WARN message must appear when mode=warn")
	}
}

func TestJSONLogger_ErrorModeFiltersWarn(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "error", Synchronous: true}, "t")
	l.Warnf("hidden warn")
	l.Errorf("visible error")

	out := buf.String()
	if strings.Contains(out, "hidden warn") {
		t.Error("WARN message must be filtered when mode=error")
	}
	if !strings.Contains(out, "visible error") {
		t.Error("ERROR message must appear when mode=error")
	}
}

// ---------------------------------------------------------------------------
// DNS query event - dns sub-object must contain all per-query fields
// ---------------------------------------------------------------------------

func TestJSONLogger_DNSQueryEvent(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "example.com A -> rcode=NOERROR")
	ev.DNS.Client = &ClientInfo{
		IP:       "192.168.1.10",
		Port:     54321,
		Protocol: "plain",
		Domain:   "example.com",
		QType:    "A",
		QClass:   "IN",
		DOBit:    false,
		EDNS:     &ClientEDNS{Present: true, UDPSize: 4096},
	}
	ev.DNS.Upstream = []*UpstreamInfo{
		{
			Index:       0,
			Address:     "https://dns.quad9.net/dns-query",
			Protocol:    "doh",
			DurationMS:  45,
			RCode:       "NOERROR",
			AnswerCount: 1,
			ResolvedIPs: []string{"1.2.3.4"},
		},
	}
	ev.DNS.Decision = &DecisionInfo{
		Blocked:      false,
		Cacheable:    true,
		AllResponded: true,
		RCode:        "NOERROR",
	}
	l.LogEvent(LevelInfo, ev)

	lines := readJSONLines(&buf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 JSON line, got %d:\n%s", len(lines), buf.String())
	}
	obj := lines[0]
	assertJSONString(t, obj, "type", TypeDNSQuery)
	assertJSONString(t, obj, "level", "INFO")

	// Per-query fields must NOT appear at top level.
	for _, forbidden := range []string{"client", "upstream", "decision", "cache"} {
		if _, has := obj[forbidden]; has {
			t.Errorf("%q must not appear at top level; it belongs inside 'dns'", forbidden)
		}
	}

	dns := dnsSubmap(t, obj)

	clientRaw, ok := dns["client"].(map[string]interface{})
	if !ok {
		t.Fatal("expected dns.client to be a JSON object")
	}
	assertJSONString(t, clientRaw, "ip", "192.168.1.10")
	assertJSONString(t, clientRaw, "protocol", "plain")
	assertJSONString(t, clientRaw, "domain", "example.com")
	assertJSONString(t, clientRaw, "qtype", "A")

	ednsRaw, ok := clientRaw["edns"].(map[string]interface{})
	if !ok {
		t.Fatal("expected dns.client.edns to be a JSON object")
	}
	if ednsRaw["present"] != true {
		t.Error("expected edns.present=true")
	}

	upstreamRaw, ok := dns["upstream"].([]interface{})
	if !ok || len(upstreamRaw) != 1 {
		t.Fatal("expected dns.upstream array with 1 element")
	}
	up0, ok := upstreamRaw[0].(map[string]interface{})
	if !ok {
		t.Fatal("expected dns.upstream[0] to be an object")
	}
	assertJSONString(t, up0, "address", "https://dns.quad9.net/dns-query")
	assertJSONString(t, up0, "rcode", "NOERROR")

	decisionRaw, ok := dns["decision"].(map[string]interface{})
	if !ok {
		t.Fatal("expected dns.decision to be a JSON object")
	}
	if decisionRaw["blocked"] != false {
		t.Error("expected decision.blocked=false")
	}
	if decisionRaw["cacheable"] != true {
		t.Error("expected decision.cacheable=true")
	}
}

func TestJSONLogger_CacheHitEvent(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)
	l.SetLevel(LevelDebug)

	ev := NewDNSQueryEvent(LevelDebug, "server", "example.com A -> cache hit")
	ev.DNS.Client = &ClientInfo{
		IP:     "10.0.0.1",
		Domain: "example.com",
		QType:  "A",
		QClass: "IN",
		EDNS:   &ClientEDNS{Present: false},
	}
	ev.DNS.Cache = &CacheInfo{Hit: true, TTLSec: 300, TTLRemainingSec: 247, TTLRemainingPct: 82.33}
	l.LogEvent(LevelDebug, ev)

	lines := readJSONLines(&buf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 JSON line, got %d:\n%s", len(lines), buf.String())
	}
	dns := dnsSubmap(t, lines[0])

	if _, has := dns["upstream"]; has {
		t.Error("cache hit dns event must not have 'upstream'")
	}
	if _, has := dns["decision"]; has {
		t.Error("cache hit dns event must not have 'decision'")
	}

	cacheRaw, ok := dns["cache"].(map[string]interface{})
	if !ok {
		t.Fatal("expected dns.cache to be a JSON object")
	}
	if cacheRaw["hit"] != true {
		t.Error("expected dns.cache.hit=true")
	}
	if ttlSec, _ := cacheRaw["ttl_sec"].(float64); ttlSec != 300 {
		t.Errorf("expected dns.cache.ttl_sec=300, got %v", cacheRaw["ttl_sec"])
	}
}

// ---------------------------------------------------------------------------
// InfofText / WarnfText suppression behaviour
// ---------------------------------------------------------------------------

func TestTextOnly_JSONMode(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	l.InfofText("blocked domain %s", "evil.example")
	l.WarnfText("slow upstream took %dms", 1200)

	if buf.Len() > 0 {
		t.Errorf("InfofText/WarnfText must produce no output in JSON-only mode, got:\n%s", buf.String())
	}
}

func TestTextOnly_TextMode(t *testing.T) {
	var buf bytes.Buffer
	l := textLogger(&buf)

	l.InfofText("blocked domain %s", "evil.example")
	l.WarnfText("slow upstream took %dms", 1200)

	out := buf.String()
	if !strings.Contains(out, "blocked domain evil.example") {
		t.Errorf("InfofText must appear in text mode, got:\n%s", out)
	}
	if !strings.Contains(out, "INFO") {
		t.Error("InfofText must use INFO level in text mode")
	}
	if !strings.Contains(out, "slow upstream took 1200ms") {
		t.Errorf("WarnfText must appear in text mode, got:\n%s", out)
	}
	if !strings.Contains(out, "WARN") {
		t.Error("WarnfText must use WARN level in text mode")
	}
}

func TestTextOnly_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "error"}, "t")

	l.InfofText("info text only message")
	l.WarnfText("warn text only message")

	if buf.Len() > 0 {
		t.Errorf("InfofText/WarnfText must be suppressed when mode=error, got:\n%s", buf.String())
	}
}

func TestTextOnly_WritesOnlyToTextNotJSON(t *testing.T) {
	var jsonBuf, textBuf bytes.Buffer

	jsonL := NewWriterLogger(&jsonBuf, Config{StdoutMode: "json", Synchronous: true}, "t")
	textL := NewWriterLogger(&textBuf, Config{StdoutMode: "info", Synchronous: true}, "t")

	jsonL.InfofText("should not appear in json buf")
	textL.InfofText("should appear in text buf")

	if jsonBuf.Len() > 0 {
		t.Errorf("InfofText must not write to JSON output, got:\n%s", jsonBuf.String())
	}
	if !strings.Contains(textBuf.String(), "should appear in text buf") {
		t.Errorf("InfofText must write to text output, got:\n%s", textBuf.String())
	}
}

// ---------------------------------------------------------------------------
// IsJSONEnabled / IsTextEnabled
// ---------------------------------------------------------------------------

func TestJSONLogger_IsJSONEnabled(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"json", true},
		{"info", false},
		{"debug", false},
		{"off", false},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		l := NewWriterLogger(&buf, Config{StdoutMode: tc.mode}, "t")
		if l.IsJSONEnabled() != tc.want {
			t.Errorf("mode=%q: IsJSONEnabled()=%v, want %v", tc.mode, l.IsJSONEnabled(), tc.want)
		}
	}
}

func TestJSONLogger_IsTextEnabled(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"info", true},
		{"debug", true},
		{"warn", true},
		{"json", false},
		{"off", false},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		l := NewWriterLogger(&buf, Config{StdoutMode: tc.mode}, "t")
		if l.IsTextEnabled() != tc.want {
			t.Errorf("mode=%q: IsTextEnabled()=%v, want %v", tc.mode, l.IsTextEnabled(), tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Blocked domain events
// ---------------------------------------------------------------------------

func TestJSONLogger_BlockedDecision(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "blocked.example A -> blocked")
	ev.DNS.Decision = &DecisionInfo{
		Blocked:     true,
		BlockedBy:   "https://dns.quad9.net/dns-query",
		BlockSource: "upstream",
		Cacheable:   true,
		RCode:       "NOERROR",
	}
	l.LogEvent(LevelInfo, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	decRaw, ok := dns["decision"].(map[string]interface{})
	if !ok {
		t.Fatal("expected dns.decision object")
	}
	if decRaw["blocked"] != true {
		t.Error("expected decision.blocked=true")
	}
	assertJSONString(t, decRaw, "blocked_by", "https://dns.quad9.net/dns-query")
	assertJSONString(t, decRaw, "block_source", "upstream")
}

func TestJSONLogger_LocalBlacklistDecision(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "evil.example A -> local blacklist")
	ev.DNS.Decision = &DecisionInfo{
		Blocked:     true,
		BlockedBy:   "local-blacklist",
		BlockSource: "local-blacklist",
		RCode:       "NOERROR",
	}
	l.LogEvent(LevelInfo, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	decRaw, _ := dns["decision"].(map[string]interface{})
	assertJSONString(t, decRaw, "block_source", "local-blacklist")
}

// ---------------------------------------------------------------------------
// Background refresh / DNSSEC / whitelist flags
// ---------------------------------------------------------------------------

func TestJSONLogger_BackgroundRefreshFlag(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)
	l.SetLevel(LevelDebug)

	ev := NewDNSQueryEvent(LevelDebug, "server", "example.com A -> stale (refresh queued)")
	ev.DNS.Cache = &CacheInfo{
		Hit:                        true,
		TTLSec:                     60,
		TTLRemainingSec:            5,
		TTLRemainingPct:            8.33,
		BackgroundRefreshTriggered: true,
	}
	l.LogEvent(LevelDebug, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	cacheRaw, _ := dns["cache"].(map[string]interface{})
	if cacheRaw["background_refresh_triggered"] != true {
		t.Error("expected background_refresh_triggered=true")
	}
}

func TestJSONLogger_DNSSECFlag(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "t", "dnssec test")
	ev.DNS.Cache = &CacheInfo{Hit: true, TTLSec: 300, TTLRemainingSec: 200, TTLRemainingPct: 66.67, DNSSEC: true}
	l.LogEvent(LevelInfo, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	cacheRaw, _ := dns["cache"].(map[string]interface{})
	if cacheRaw["dnssec"] != true {
		t.Error("expected dns.cache.dnssec=true")
	}
}

func TestJSONLogger_WhitelistedCacheEntry(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)
	l.SetLevel(LevelDebug)

	ev := NewDNSQueryEvent(LevelDebug, "t", "whitelist cache test")
	ev.DNS.Cache = &CacheInfo{Hit: true, TTLSec: 86400, Whitelisted: true}
	l.LogEvent(LevelDebug, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	cacheRaw, _ := dns["cache"].(map[string]interface{})
	if cacheRaw["whitelisted"] != true {
		t.Error("expected dns.cache.whitelisted=true")
	}
}

// ---------------------------------------------------------------------------
// IDN / internationalized domain names
// ---------------------------------------------------------------------------

func TestJSONLogger_IDNDomainEncoding(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "IDN test")
	ev.DNS.Client = &ClientInfo{
		Domain:    "\u4e2d\u6587.example",
		DomainACE: "xn--fiq228c.example",
		QType:     "A",
		QClass:    "IN",
		EDNS:      &ClientEDNS{Present: false},
	}
	l.LogEvent(LevelInfo, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	clientRaw, _ := dns["client"].(map[string]interface{})
	domainVal, _ := clientRaw["domain"].(string)
	if domainVal == "" || domainVal == "xn--fiq228c.example" {
		t.Errorf("expected Unicode domain, got %q", domainVal)
	}
	aceVal, _ := clientRaw["domain_ace"].(string)
	if aceVal != "xn--fiq228c.example" {
		t.Errorf("expected domain_ace=xn--fiq228c.example, got %q", aceVal)
	}
}

func TestJSONLogger_ASCIIDomainNoDomainACE(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "ASCII domain test")
	ev.DNS.Client = &ClientInfo{
		Domain:    "example.com",
		DomainACE: "",
		QType:     "A",
		QClass:    "IN",
		EDNS:      &ClientEDNS{Present: false},
	}
	l.LogEvent(LevelInfo, ev)

	if strings.Contains(buf.String(), "domain_ace") {
		t.Errorf("domain_ace must be absent for ASCII-only domains, got: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// Multiple upstreams and slow flag
// ---------------------------------------------------------------------------

func TestJSONLogger_MultipleUpstreams(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "multi-upstream test")
	ev.DNS.Upstream = []*UpstreamInfo{
		{Index: 0, Protocol: "doh", DurationMS: 40, RCode: "NOERROR"},
		{Index: 1, Protocol: "doh", DurationMS: 65, RCode: "NOERROR"},
	}
	ev.DNS.Decision = &DecisionInfo{AllResponded: true, RCode: "NOERROR"}
	l.LogEvent(LevelInfo, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	upArr, ok := dns["upstream"].([]interface{})
	if !ok || len(upArr) != 2 {
		t.Fatalf("expected dns.upstream with 2 elements, got %v", dns["upstream"])
	}
	up0, _ := upArr[0].(map[string]interface{})
	up1, _ := upArr[1].(map[string]interface{})
	if idx0, _ := up0["index"].(float64); idx0 != 0 {
		t.Errorf("expected upstream[0].index=0, got %v", idx0)
	}
	if idx1, _ := up1["index"].(float64); idx1 != 1 {
		t.Errorf("expected upstream[1].index=1, got %v", idx1)
	}
}

func TestJSONLogger_SlowUpstreamFlag(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelWarn, "server", "slow upstream test")
	ev.DNS.Upstream = []*UpstreamInfo{
		{Index: 0, Protocol: "doh", DurationMS: 1807, Slow: true},
	}
	l.LogEvent(LevelWarn, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	upArr, _ := dns["upstream"].([]interface{})
	up0, _ := upArr[0].(map[string]interface{})
	if up0["slow"] != true {
		t.Error("expected upstream[0].slow=true")
	}
	if ms, _ := up0["duration_ms"].(float64); ms != 1807 {
		t.Errorf("expected duration_ms=1807, got %v", ms)
	}
}

func TestJSONLogger_UpstreamError(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelWarn, "t", "upstream error test")
	ev.DNS.Upstream = []*UpstreamInfo{
		{Index: 0, Protocol: "udp", ServFail: true, Error: "context deadline exceeded"},
	}
	l.LogEvent(LevelWarn, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	upArr, _ := dns["upstream"].([]interface{})
	up0, _ := upArr[0].(map[string]interface{})
	if up0["servfail"] != true {
		t.Error("expected upstream.servfail=true")
	}
	errVal, _ := up0["error"].(string)
	if !strings.Contains(errVal, "deadline") {
		t.Errorf("expected error containing 'deadline', got %q", errVal)
	}
}

func TestJSONLogger_ResolvedIPs(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "t", "resolved IPs test")
	ev.DNS.Upstream = []*UpstreamInfo{
		{Index: 0, Protocol: "doh", RCode: "NOERROR", AnswerCount: 2, ResolvedIPs: []string{"1.2.3.4", "5.6.7.8"}},
	}
	l.LogEvent(LevelInfo, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	upArr, _ := dns["upstream"].([]interface{})
	up0, _ := upArr[0].(map[string]interface{})
	ips, ok := up0["resolved_ips"].([]interface{})
	if !ok || len(ips) != 2 {
		t.Fatalf("expected resolved_ips with 2 entries, got %v", up0["resolved_ips"])
	}
}

// ---------------------------------------------------------------------------
// Constructor helpers
// ---------------------------------------------------------------------------

func TestJSONLogger_NewGeneralEvent(t *testing.T) {
	ev := NewGeneralEvent(LevelWarn, "mymod", "test warning")
	if ev.Type != TypeGeneral {
		t.Errorf("expected type=%q, got %q", TypeGeneral, ev.Type)
	}
	if ev.Level != "WARN" {
		t.Errorf("expected level=WARN, got %q", ev.Level)
	}
	if ev.DNS != nil {
		t.Error("general event must have nil DNS field")
	}
	if ev.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestJSONLogger_NewDNSQueryEvent(t *testing.T) {
	ev := NewDNSQueryEvent(LevelInfo, "server", "dns test")
	if ev.Type != TypeDNSQuery {
		t.Errorf("expected type=%q, got %q", TypeDNSQuery, ev.Type)
	}
	if ev.DNS == nil {
		t.Fatal("NewDNSQueryEvent must initialize DNS field")
	}
	if ev.DNS.Client != nil || ev.DNS.Upstream != nil || ev.DNS.Decision != nil || ev.DNS.Cache != nil {
		t.Error("new DNS event must have all dns sub-fields nil by default")
	}
}

// ---------------------------------------------------------------------------
// LogEvent level filtering
// ---------------------------------------------------------------------------

func TestJSONLogger_EventRespectsBothLevelsAndJSON(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)
	l.SetLevel(LevelWarn)

	l.LogEvent(LevelDebug, NewDNSQueryEvent(LevelDebug, "t", "debug event"))
	if buf.Len() > 0 {
		t.Errorf("DEBUG event must be suppressed at WARN level, got: %s", buf.String())
	}

	l.LogEvent(LevelWarn, NewDNSQueryEvent(LevelWarn, "t", "warn event"))
	if buf.Len() == 0 {
		t.Error("WARN event must be logged at WARN level")
	}
}

// ---------------------------------------------------------------------------
// EDNS details
// ---------------------------------------------------------------------------

func TestJSONLogger_EDNSDetails(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "t", "edns test")
	ev.DNS.Client = &ClientInfo{
		Protocol: "doh",
		Domain:   "example.com",
		QType:    "A",
		QClass:   "IN",
		DOBit:    true,
		EDNS:     &ClientEDNS{Present: true, UDPSize: 4096, PaddingRequested: true},
	}
	l.LogEvent(LevelInfo, ev)

	dns := dnsSubmap(t, readJSONLines(&buf)[0])
	clientRaw, _ := dns["client"].(map[string]interface{})
	if clientRaw["do_bit"] != true {
		t.Error("expected do_bit=true")
	}
	ednsRaw, _ := clientRaw["edns"].(map[string]interface{})
	if ednsRaw["present"] != true {
		t.Error("expected edns.present=true")
	}
	if ednsRaw["padding_requested"] != true {
		t.Error("expected edns.padding_requested=true")
	}
	if udp, _ := ednsRaw["udp_size"].(float64); udp != 4096 {
		t.Errorf("expected edns.udp_size=4096, got %v", ednsRaw["udp_size"])
	}
}

// ---------------------------------------------------------------------------
// JSON mode uses INFO as minimum level
// ---------------------------------------------------------------------------

func TestJSONLogger_JSONModeIsInfoLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "json"}, "t")
	if l.stdoutMin != LevelInfo {
		t.Errorf("json mode must use LevelInfo min, got %v", l.stdoutMin)
	}
}

// ---------------------------------------------------------------------------
// SetLevel / updateMinLevel integration
// ---------------------------------------------------------------------------

func TestLogger_SetLevelUpdatesMinLevel(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)
	if l.minLevel != LevelInfo {
		t.Errorf("expected minLevel=INFO after json construction, got %v", l.minLevel)
	}

	l.SetLevel(LevelError)
	if l.minLevel != LevelError {
		t.Errorf("expected minLevel=ERROR after SetLevel(Error), got %v", l.minLevel)
	}

	l.Warnf("should be suppressed")
	if buf.Len() > 0 {
		t.Errorf("WARN must be suppressed after SetLevel(Error), got: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// ResponseInfo — what was actually sent back to the client
// ---------------------------------------------------------------------------

// responseSubmap extracts dns.response from a top-level JSON event.
func responseSubmap(t *testing.T, obj map[string]interface{}) map[string]interface{} {
	t.Helper()
	dns := dnsSubmap(t, obj)
	raw, ok := dns["response"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected 'dns.response' to be a JSON object, got %T: %v", dns["response"], dns["response"])
	}
	return raw
}

func TestJSONLogger_ResponseInfo_UpstreamQuery(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "example.com A -> rcode=NOERROR")
	ev.DNS.Response = &ResponseInfo{
		RCode:       "NOERROR",
		AnswerCount: 2,
		IPs:         []string{"1.2.3.4", "5.6.7.8"},
	}
	l.LogEvent(LevelInfo, ev)

	resp := responseSubmap(t, readJSONLines(&buf)[0])
	assertJSONString(t, resp, "rcode", "NOERROR")
	ips, ok := resp["ips"].([]interface{})
	if !ok || len(ips) != 2 {
		t.Fatalf("expected dns.response.ips with 2 entries, got %v", resp["ips"])
	}
	if ips[0].(string) != "1.2.3.4" {
		t.Errorf("expected ips[0]=1.2.3.4, got %v", ips[0])
	}
	if ips[1].(string) != "5.6.7.8" {
		t.Errorf("expected ips[1]=5.6.7.8, got %v", ips[1])
	}
	if ac, _ := resp["answer_count"].(float64); ac != 2 {
		t.Errorf("expected answer_count=2, got %v", resp["answer_count"])
	}
}

func TestJSONLogger_ResponseInfo_CacheHit(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)
	l.SetLevel(LevelDebug)

	ev := NewDNSQueryEvent(LevelDebug, "server", "example.com A -> cache hit")
	ev.DNS.Cache = &CacheInfo{Hit: true, TTLSec: 300, TTLRemainingSec: 200, TTLRemainingPct: 66.67}
	ev.DNS.Response = &ResponseInfo{
		RCode:       "NOERROR",
		AnswerCount: 1,
		IPs:         []string{"9.9.9.9"},
	}
	l.LogEvent(LevelDebug, ev)

	resp := responseSubmap(t, readJSONLines(&buf)[0])
	assertJSONString(t, resp, "rcode", "NOERROR")
	ips, _ := resp["ips"].([]interface{})
	if len(ips) != 1 || ips[0].(string) != "9.9.9.9" {
		t.Errorf("expected ips=[9.9.9.9], got %v", resp["ips"])
	}
}

func TestJSONLogger_ResponseInfo_BlockedNoIPs(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "evil.com A -> blocked")
	ev.DNS.Decision = &DecisionInfo{Blocked: true, BlockedBy: "local-blacklist", BlockSource: "local-blacklist", RCode: "NOERROR"}
	// Blocked responses have no A/AAAA records (0.0.0.0 sinkhole or NXDOMAIN).
	ev.DNS.Response = &ResponseInfo{
		RCode:       "NOERROR",
		AnswerCount: 1,
	}
	l.LogEvent(LevelInfo, ev)

	resp := responseSubmap(t, readJSONLines(&buf)[0])
	assertJSONString(t, resp, "rcode", "NOERROR")
	if _, hasIPs := resp["ips"]; hasIPs {
		t.Error("blocked response with no IPs must omit the 'ips' field")
	}
}

func TestJSONLogger_ResponseInfo_NXDOMAIN(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "notexist.example A -> NXDOMAIN")
	ev.DNS.Response = &ResponseInfo{
		RCode:       "NXDOMAIN",
		AnswerCount: 0,
	}
	l.LogEvent(LevelInfo, ev)

	resp := responseSubmap(t, readJSONLines(&buf)[0])
	assertJSONString(t, resp, "rcode", "NXDOMAIN")
	if _, hasIPs := resp["ips"]; hasIPs {
		t.Error("NXDOMAIN response must not have 'ips'")
	}
	if _, hasAC := resp["answer_count"]; hasAC {
		t.Error("NXDOMAIN response with 0 answers must omit answer_count (omitempty)")
	}
}

func TestJSONLogger_ResponseInfo_SERVFAIL(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelWarn, "server", "fail.example A -> SERVFAIL")
	ev.DNS.Response = &ResponseInfo{
		RCode:       "SERVFAIL",
		AnswerCount: 0,
	}
	l.LogEvent(LevelWarn, ev)

	resp := responseSubmap(t, readJSONLines(&buf)[0])
	assertJSONString(t, resp, "rcode", "SERVFAIL")
}

func TestJSONLogger_ResponseInfo_Truncated(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "big.example ANY -> TC=1")
	ev.DNS.Response = &ResponseInfo{
		RCode:       "NOERROR",
		AnswerCount: 0,
		Truncated:   true,
	}
	l.LogEvent(LevelInfo, ev)

	resp := responseSubmap(t, readJSONLines(&buf)[0])
	if resp["truncated"] != true {
		t.Errorf("expected dns.response.truncated=true, got %v", resp["truncated"])
	}
}

func TestJSONLogger_ResponseInfo_TruncatedFalseOmitted(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "example.com A -> NOERROR")
	ev.DNS.Response = &ResponseInfo{
		RCode:       "NOERROR",
		AnswerCount: 1,
		IPs:         []string{"1.2.3.4"},
		Truncated:   false,
	}
	l.LogEvent(LevelInfo, ev)

	line := buf.String()
	if strings.Contains(line, "\"truncated\"") {
		t.Error("truncated=false must be omitted from JSON (omitempty)")
	}
}

func TestJSONLogger_ResponseInfo_MultipleIPv6(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	ev := NewDNSQueryEvent(LevelInfo, "server", "example.com AAAA -> NOERROR")
	ev.DNS.Response = &ResponseInfo{
		RCode:       "NOERROR",
		AnswerCount: 3,
		IPs:         []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"},
	}
	l.LogEvent(LevelInfo, ev)

	resp := responseSubmap(t, readJSONLines(&buf)[0])
	ips, ok := resp["ips"].([]interface{})
	if !ok || len(ips) != 3 {
		t.Fatalf("expected 3 IPv6 addresses, got %v", resp["ips"])
	}
}

func TestJSONLogger_ResponseInfo_AbsentWhenNilForGeneralEvent(t *testing.T) {
	var buf bytes.Buffer
	l := jsonLogger(&buf)

	// General events have no DNS field at all.
	l.Infof("startup complete")

	obj := readJSONLines(&buf)[0]
	if _, hasDNS := obj["dns"]; hasDNS {
		t.Error("general event must not have a 'dns' field")
	}
}

func TestJSONLogger_ResponseInfo_PresentInAllDNSQueryPaths(t *testing.T) {
	// Verify that when Response is populated, it always appears under dns.response.
	cases := []struct {
		name string
		ev   *Event
	}{
		{
			"upstream",
			func() *Event {
				e := NewDNSQueryEvent(LevelInfo, "t", "upstream")
				e.DNS.Decision = &DecisionInfo{RCode: "NOERROR"}
				e.DNS.Response = &ResponseInfo{RCode: "NOERROR", AnswerCount: 1, IPs: []string{"1.1.1.1"}}
				return e
			}(),
		},
		{
			"cache_hit",
			func() *Event {
				e := NewDNSQueryEvent(LevelInfo, "t", "cache")
				e.DNS.Cache = &CacheInfo{Hit: true, TTLSec: 60}
				e.DNS.Response = &ResponseInfo{RCode: "NOERROR", AnswerCount: 1, IPs: []string{"2.2.2.2"}}
				return e
			}(),
		},
		{
			"blocked",
			func() *Event {
				e := NewDNSQueryEvent(LevelInfo, "t", "blocked")
				e.DNS.Decision = &DecisionInfo{Blocked: true, BlockSource: "local-blacklist", RCode: "NOERROR"}
				e.DNS.Response = &ResponseInfo{RCode: "NOERROR"}
				return e
			}(),
		},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		l := jsonLogger(&buf)
		l.LogEvent(LevelInfo, tc.ev)
		lines := readJSONLines(&buf)
		if len(lines) != 1 {
			t.Errorf("%s: expected 1 JSON line, got %d", tc.name, len(lines))
			continue
		}
		dns := dnsSubmap(t, lines[0])
		if _, ok := dns["response"].(map[string]interface{}); !ok {
			t.Errorf("%s: expected dns.response to be present and be an object", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------
// Pool-based write path — verify no data corruption under concurrent use
// ---------------------------------------------------------------------------

func TestJSONLogger_ConcurrentWrites(t *testing.T) {
	// Sanity check: concurrent LogEvent calls must not interleave JSON lines
	// or produce garbled output. Each goroutine writes its own index; we verify
	// all lines parse correctly.
	var mu sync.Mutex
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "json", Synchronous: true}, "conctest")
	l.SetLevel(LevelDebug)

	const workers = 8
	const perWorker = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				ev := NewDNSQueryEvent(LevelDebug, "t", "concurrent test")
				ev.DNS.Response = &ResponseInfo{RCode: "NOERROR", AnswerCount: 1}
				l.LogEvent(LevelDebug, ev)
			}
		}(i)
	}
	wg.Wait()

	mu.Lock()
	lines := readJSONLines(&buf)
	mu.Unlock()
	if len(lines) != workers*perWorker {
		t.Errorf("expected %d JSON lines, got %d", workers*perWorker, len(lines))
	}
	for i, line := range lines {
		if line["type"] != TypeDNSQuery {
			t.Errorf("line %d: expected type=%q, got %v", i, TypeDNSQuery, line["type"])
		}
	}
}

// ---------------------------------------------------------------------------
// dns_query events are JSON-only — no text output regardless of mode
// ---------------------------------------------------------------------------

func TestDNSQueryEvent_TextModeProducesNoOutput(t *testing.T) {
	for _, mode := range []string{"debug", "info", "warn"} {
		var buf bytes.Buffer
		l := NewWriterLogger(&buf, Config{StdoutMode: mode, Synchronous: true}, "t")
		l.SetLevel(LevelDebug)
		ev := NewDNSQueryEvent(LevelInfo, "t", "should not appear in text mode")
		l.LogEvent(LevelInfo, ev)
		if buf.Len() > 0 {
			t.Errorf("mode=%s: dns_query event must not appear in text output, got: %s", mode, buf.String())
		}
	}
}

func TestDNSQueryEvent_JSONModeProducesOutput(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "json", Synchronous: true}, "t")
	ev := NewDNSQueryEvent(LevelInfo, "t", "should appear in json mode")
	l.LogEvent(LevelInfo, ev)
	if buf.Len() == 0 {
		t.Error("dns_query event must produce JSON output when StdoutMode=json")
	}
	lines := readJSONLines(&buf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 JSON line, got %d: %s", len(lines), buf.String())
	}
	if lines[0]["type"] != TypeDNSQuery {
		t.Errorf("expected type=%q, got %v", TypeDNSQuery, lines[0]["type"])
	}
}

func TestDNSQueryEvent_DroppedWithoutJSONMode(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "info", Synchronous: true}, "t")
	l.SetLevel(LevelDebug)
	ev := NewDNSQueryEvent(LevelDebug, "t", "dropped event")
	l.LogEvent(LevelDebug, ev)
	if buf.Len() > 0 {
		t.Errorf("dns_query event must be dropped entirely when no JSON output configured, got: %s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// JSON mode minimum level is INFO — DEBUG messages are filtered
// ---------------------------------------------------------------------------

func TestJSONMode_DebugMessageIsFiltered(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "json", Synchronous: true}, "t")
	l.Debugf("debug message should not appear")
	if buf.Len() > 0 {
		t.Errorf("DEBUG general message must be filtered in json mode, got: %s", buf.String())
	}
}

func TestJSONMode_InfoMessageIsNotFiltered(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "json", Synchronous: true}, "t")
	l.Infof("info message should appear")
	if buf.Len() == 0 {
		t.Error("INFO general message must not be filtered in json mode")
	}
}

// ---------------------------------------------------------------------------
// General (non-dns_query) events still appear in text mode
// ---------------------------------------------------------------------------

func TestGeneralEvent_AppearsInTextMode(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf, Config{StdoutMode: "info", Synchronous: true}, "t")
	l.Infof("general info message")
	if buf.Len() == 0 {
		t.Error("general INFO message must appear in text (info) mode")
	}
	if strings.Contains(buf.String(), "{") {
		t.Errorf("text mode must not produce JSON for general messages, got: %s", buf.String())
	}
}
