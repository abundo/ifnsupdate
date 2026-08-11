package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v3"
)

const (
	defaultRetryInterval        = 5 * time.Minute
	defaultStaticVerifyInterval = time.Hour
)

// recordScope selects which configured records a reconcile pass considers.
type recordScope int

const (
	scopeAll recordScope = iota
	scopeDynamic
	scopeStatic
)

type Config struct {
	Interface            string    `yaml:"interface"`
	DNS                  DNSConfig `yaml:"dns"`
	Records              []Record  `yaml:"records"`
	RetryInterval        string    `yaml:"retry_interval"`         // Go duration, e.g. "5m"
	StaticVerifyInterval string    `yaml:"static_verify_interval"` // Go duration, e.g. "1h"

	// Parsed durations (filled by validateConfig).
	retryInterval        time.Duration
	staticVerifyInterval time.Duration
}

type DNSConfig struct {
	Server string      `yaml:"server"` // e.g. "ns1.example.com:53"
	Zone   string      `yaml:"zone"`   // e.g. "example.com."
	TSIG   *TSIGConfig `yaml:"tsig,omitempty"`
}

type TSIGConfig struct {
	Name      string `yaml:"name"`      // e.g. "keyname."
	Secret    string `yaml:"secret"`    // base64-encoded secret
	Algorithm string `yaml:"algorithm"` // e.g. "hmac-sha256"
}

// Record is a DNS name to maintain.
//
// A/AAAA without value are filled from the monitored interface.
// A/AAAA with value, CNAME, and TXT with value are static.
// TXT without value is a last-update timestamp (ISO 8601 / RFC3339).
type Record struct {
	Name  string `yaml:"name"`  // relative to zone (e.g. "host") or FQDN in zone
	Type  string `yaml:"type"`  // "A", "AAAA", "CNAME", or "TXT"
	TTL   uint32 `yaml:"ttl"`   // seconds
	Value string `yaml:"value"` // static RDATA: IP, CNAME target, or TXT string; empty TXT = timestamp
}

// isTimestamp reports whether rec is a last-update TXT (type TXT, no value).
// Its RDATA is set to the current UTC time in RFC3339 form whenever an UPDATE runs.
func (r Record) isTimestamp() bool {
	return r.Type == "TXT" && r.Value == ""
}

// isStatic reports whether rec is not derived from the interface address
// and is not a last-update timestamp.
func (r Record) isStatic() bool {
	switch r.Type {
	case "CNAME":
		return true
	case "TXT":
		// Non-empty value is a fixed string; empty is a dynamic timestamp.
		return r.Value != ""
	case "A", "AAAA":
		return r.Value != ""
	default:
		return false
	}
}

// nowFunc is the clock used for timestamp TXT records. Tests may replace it.
var nowFunc = time.Now

// timestampTXTValue returns the RDATA for a last-update timestamp TXT.
func timestampTXTValue() string {
	return nowFunc().UTC().Format(time.RFC3339)
}

// nameInZone reports whether name is the zone apex or a strict subdomain of zone.
// name and zone must be absolute FQDNs (trailing dots). Comparison is case-insensitive.
func nameInZone(name, zone string) bool {
	n := strings.ToLower(name)
	z := strings.ToLower(zone)
	return n == z || strings.HasSuffix(n, "."+z)
}

// normalizeRecordName resolves recName against zone.
//
//   - "@" is the zone apex
//   - absolute names (trailing ".") must lie in the zone
//   - names that already end with the zone labels (with or without a trailing ".")
//     are treated as FQDNs in the zone
//   - other names without a trailing "." are relative and have the zone appended
func normalizeRecordName(recName, zone string) (string, error) {
	recName = strings.TrimSpace(recName)
	if recName == "" {
		return "", fmt.Errorf("is required")
	}
	if recName == "@" {
		return zone, nil
	}

	absolute := strings.HasSuffix(recName, ".")
	candidate := recName
	if !absolute {
		candidate = recName + "."
	}

	if nameInZone(candidate, zone) {
		return candidate, nil
	}
	if absolute {
		return "", fmt.Errorf("%q is not in zone %q", recName, zone)
	}
	return recName + "." + zone, nil
}

// normalizeCNAMETarget resolves a CNAME target. Absolute names (trailing ".") are
// kept as-is (may point outside the zone). Relative names are treated like record
// names against the zone.
func normalizeCNAMETarget(target, zone string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("is required")
	}
	if target == "@" {
		return zone, nil
	}
	if strings.HasSuffix(target, ".") {
		return target, nil
	}
	// Already ends with zone labels without trailing dot → FQDN in zone.
	candidate := target + "."
	if nameInZone(candidate, zone) {
		return candidate, nil
	}
	return target + "." + zone, nil
}

// lastIPs is the last successfully published addresses (single-goroutine use).
type lastIPs struct {
	v4, v6 net.IP
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func parseDurationField(name, raw string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return d, nil
}

// validateDNSConfig normalizes and checks dns.server, dns.zone, and optional TSIG.
// Used by full config validation and by one-shot modes that only talk to the nameserver.
func validateDNSConfig(cfg *Config) error {
	if cfg.DNS.Server == "" {
		return fmt.Errorf("dns.server is required")
	}
	if cfg.DNS.Zone == "" {
		return fmt.Errorf("dns.zone is required")
	}
	if !strings.HasSuffix(cfg.DNS.Zone, ".") {
		cfg.DNS.Zone += "."
	}
	if cfg.DNS.TSIG != nil {
		if cfg.DNS.TSIG.Name == "" || cfg.DNS.TSIG.Secret == "" {
			return fmt.Errorf("tsig.name and tsig.secret are required when tsig is set")
		}
		if !strings.HasSuffix(cfg.DNS.TSIG.Name, ".") {
			cfg.DNS.TSIG.Name += "."
		}
		if cfg.DNS.TSIG.Algorithm == "" {
			cfg.DNS.TSIG.Algorithm = "hmac-sha256"
		}
	}
	return nil
}

func validateConfig(cfg *Config) error {
	if cfg.Interface == "" {
		return fmt.Errorf("interface is required")
	}
	if err := validateDNSConfig(cfg); err != nil {
		return err
	}

	var err error
	cfg.retryInterval, err = parseDurationField("retry_interval", cfg.RetryInterval, defaultRetryInterval)
	if err != nil {
		return err
	}
	cfg.staticVerifyInterval, err = parseDurationField("static_verify_interval", cfg.StaticVerifyInterval, defaultStaticVerifyInterval)
	if err != nil {
		return err
	}

	if len(cfg.Records) == 0 {
		return fmt.Errorf("at least one record is required")
	}
	for i, r := range cfg.Records {
		name, err := normalizeRecordName(r.Name, cfg.DNS.Zone)
		if err != nil {
			return fmt.Errorf("records[%d].name %w", i, err)
		}
		cfg.Records[i].Name = name
		t := strings.ToUpper(strings.TrimSpace(r.Type))
		cfg.Records[i].Type = t
		if r.TTL == 0 {
			cfg.Records[i].TTL = 300
		}
		value := strings.TrimSpace(r.Value)
		cfg.Records[i].Value = value

		switch t {
		case "A", "AAAA":
			if value != "" {
				ip := net.ParseIP(value)
				if ip == nil {
					return fmt.Errorf("records[%d].value is not a valid IP address", i)
				}
				if t == "A" && ip.To4() == nil {
					return fmt.Errorf("records[%d].value must be an IPv4 address for type A", i)
				}
				if t == "AAAA" && ip.To4() != nil {
					return fmt.Errorf("records[%d].value must be an IPv6 address for type AAAA", i)
				}
				// Normalize IP string form.
				if t == "A" {
					cfg.Records[i].Value = ip.To4().String()
				} else {
					cfg.Records[i].Value = ip.String()
				}
			}
		case "CNAME":
			if value == "" {
				return fmt.Errorf("records[%d].value is required for CNAME", i)
			}
			target, err := normalizeCNAMETarget(value, cfg.DNS.Zone)
			if err != nil {
				return fmt.Errorf("records[%d].value %w", i, err)
			}
			cfg.Records[i].Value = target
		case "TXT":
			// Empty value: last-update timestamp (RFC3339). Non-empty: static string.
		default:
			return fmt.Errorf("records[%d].type must be A, AAAA, CNAME, or TXT", i)
		}
	}
	return nil
}

func filterRecords(recs []Record, scope recordScope) []Record {
	if scope == scopeAll {
		return recs
	}
	out := make([]Record, 0, len(recs))
	for _, r := range recs {
		// Last-update timestamps ride along with every reconcile scope so any
		// successful UPDATE refreshes the "when last updated" marker.
		if r.isTimestamp() {
			out = append(out, r)
			continue
		}
		static := r.isStatic()
		if scope == scopeStatic && static {
			out = append(out, r)
		}
		if scope == scopeDynamic && !static {
			out = append(out, r)
		}
	}
	return out
}

func hasStaticRecords(cfg *Config) bool {
	for _, r := range cfg.Records {
		if r.isStatic() {
			return true
		}
	}
	return false
}

// expectedIP returns the address that should be published for a dynamic A/AAAA
// record, or nil if none is available on the interface.
func expectedIP(rec Record, v4, v6 net.IP) net.IP {
	if rec.isStatic() {
		return net.ParseIP(rec.Value)
	}
	switch rec.Type {
	case "A":
		return v4
	case "AAAA":
		return v6
	default:
		return nil
	}
}

// buildRR constructs the dns.RR to publish for rec.
func buildRR(rec Record, v4, v6 net.IP) (dns.RR, string, error) {
	switch rec.Type {
	case "A", "AAAA":
		ip := expectedIP(rec, v4, v6)
		if ip == nil {
			return nil, "", fmt.Errorf("no %s address on interface for %s", rec.Type, rec.Name)
		}
		rrStr := fmt.Sprintf("%s %d IN %s %s", rec.Name, rec.TTL, rec.Type, ip)
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			return nil, "", fmt.Errorf("invalid RR %q: %w", rrStr, err)
		}
		return rr, ip.String(), nil
	case "CNAME":
		rrStr := fmt.Sprintf("%s %d IN CNAME %s", rec.Name, rec.TTL, rec.Value)
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			return nil, "", fmt.Errorf("invalid RR %q: %w", rrStr, err)
		}
		return rr, rec.Value, nil
	case "TXT":
		val := rec.Value
		if rec.isTimestamp() {
			val = timestampTXTValue()
		}
		// Quote so spaces and special characters are valid presentation format.
		rrStr := fmt.Sprintf("%s %d IN TXT %q", rec.Name, rec.TTL, val)
		rr, err := dns.NewRR(rrStr)
		if err != nil {
			return nil, "", fmt.Errorf("invalid RR %q: %w", rrStr, err)
		}
		return rr, val, nil
	default:
		return nil, "", fmt.Errorf("unsupported type %q", rec.Type)
	}
}

// dnsQuery exchanges a non-recursive query against the configured nameserver.
func dnsQuery(cfg *Config, name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false

	client := &dns.Client{Net: "udp", Timeout: 10 * time.Second}
	resp, _, err := client.Exchange(msg, cfg.DNS.Server)
	if err != nil {
		return nil, fmt.Errorf("DNS query %s: %w", name, err)
	}
	return resp, nil
}

// queryRecordIPs asks the configured nameserver for A or AAAA answers (non-recursive).
// An empty slice means NXDOMAIN or no matching answers. Query failures return an error.
func queryRecordIPs(cfg *Config, name, qtype string) ([]net.IP, error) {
	var qt uint16
	switch qtype {
	case "A":
		qt = dns.TypeA
	case "AAAA":
		qt = dns.TypeAAAA
	default:
		return nil, fmt.Errorf("unsupported query type %q", qtype)
	}

	resp, err := dnsQuery(cfg, name, qt)
	if err != nil {
		return nil, fmt.Errorf("DNS query %s %s: %w", name, qtype, err)
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query %s %s rejected: %s", name, qtype, dns.RcodeToString[resp.Rcode])
	}

	var ips []net.IP
	for _, rr := range resp.Answer {
		switch r := rr.(type) {
		case *dns.A:
			if qtype == "A" {
				ips = append(ips, r.A)
			}
		case *dns.AAAA:
			if qtype == "AAAA" {
				ips = append(ips, r.AAAA)
			}
		}
	}
	return ips, nil
}

// recordMatches reports whether the nameserver already has exactly the expected
// RDATA for rec. On query failure it returns false so the caller can fall back to UPDATE.
func recordMatches(cfg *Config, rec Record, v4, v6 net.IP) (bool, error) {
	switch rec.Type {
	case "A", "AAAA":
		want := expectedIP(rec, v4, v6)
		if want == nil {
			return false, nil
		}
		got, err := queryRecordIPs(cfg, rec.Name, rec.Type)
		if err != nil {
			return false, err
		}
		if len(got) != 1 || !got[0].Equal(want) {
			return false, nil
		}
		return true, nil

	case "CNAME":
		resp, err := dnsQuery(cfg, rec.Name, dns.TypeCNAME)
		if err != nil {
			return false, err
		}
		if resp.Rcode == dns.RcodeNameError {
			return false, nil
		}
		if resp.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("DNS query %s CNAME rejected: %s", rec.Name, dns.RcodeToString[resp.Rcode])
		}
		var targets []string
		for _, rr := range resp.Answer {
			if c, ok := rr.(*dns.CNAME); ok {
				targets = append(targets, strings.ToLower(c.Target))
			}
		}
		if len(targets) != 1 || targets[0] != strings.ToLower(rec.Value) {
			return false, nil
		}
		return true, nil

	case "TXT":
		resp, err := dnsQuery(cfg, rec.Name, dns.TypeTXT)
		if err != nil {
			return false, err
		}
		if resp.Rcode == dns.RcodeNameError {
			return false, nil
		}
		if resp.Rcode != dns.RcodeSuccess {
			return false, fmt.Errorf("DNS query %s TXT rejected: %s", rec.Name, dns.RcodeToString[resp.Rcode])
		}
		// Accept a single TXT RR whose concatenated character-strings equal value.
		var texts []string
		for _, rr := range resp.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				texts = append(texts, strings.Join(t.Txt, ""))
			}
		}
		if len(texts) != 1 {
			return false, nil
		}
		// Timestamp TXT: any single existing RR is fine. We only rewrite it when
		// some other record in the same UPDATE batch needs fixing (or it is missing),
		// so an old ISO timestamp is left alone and still means "last update time".
		if rec.isTimestamp() {
			return true, nil
		}
		if texts[0] != rec.Value {
			return false, nil
		}
		return true, nil

	default:
		return false, fmt.Errorf("unsupported type %q", rec.Type)
	}
}

// recordsNeedUpdate queries each record in recs and returns true if any does not
// already match the desired RDATA. Missing interface addresses for dynamic A/AAAA
// count as needing update. Query failures are treated as needing update.
func recordsNeedUpdate(cfg *Config, recs []Record, v4, v6 net.IP) bool {
	need := false
	for _, rec := range recs {
		if (rec.Type == "A" || rec.Type == "AAAA") && !rec.isStatic() {
			if expectedIP(rec, v4, v6) == nil {
				slog.Info("record needs update", "name", rec.Name, "type", rec.Type, "reason", "no matching address on interface")
				need = true
				continue
			}
		}
		ok, err := recordMatches(cfg, rec, v4, v6)
		if err != nil {
			slog.Warn("DNS verify query failed; will update", "name", rec.Name, "type", rec.Type, "err", err)
			need = true
			continue
		}
		if !ok {
			want := rec.Value
			if rec.Type == "A" || rec.Type == "AAAA" {
				if ip := expectedIP(rec, v4, v6); ip != nil {
					want = ip.String()
				}
			} else if rec.isTimestamp() {
				want = "(timestamp)"
			}
			slog.Info("record incorrect or missing", "name", rec.Name, "type", rec.Type, "want", want)
			need = true
			continue
		}
		slog.Info("record already correct", "name", rec.Name, "type", rec.Type)
	}
	return need
}

// verifyAfterUpdateDelay is how long to wait after a successful UPDATE before querying
// the nameserver to confirm the change. Tests may set this to 0.
var verifyAfterUpdateDelay = 2 * time.Second

// maxUpdateAttempts is the number of UPDATE+verify cycles before giving up on a single
// reconcile attempt (the event loop then schedules a later retry).
const maxUpdateAttempts = 2

// readInterfaceAddrs reads global addresses for ifIndex. Tests may replace this.
var readInterfaceAddrs = getGlobalAddrs

// updateAndVerify sends a DNS UPDATE for recs, waits briefly, then confirms the
// nameserver reflects the desired data. If verification fails, the UPDATE is retried
// once. The cache should only be advanced when this returns nil.
func updateAndVerify(cfg *Config, recs []Record, v4, v6 net.IP) error {
	if len(recs) == 0 {
		return nil
	}
	for attempt := 1; attempt <= maxUpdateAttempts; attempt++ {
		if err := performDNSUpdate(cfg, recs, v4, v6); err != nil {
			return err
		}
		if verifyAfterUpdateDelay > 0 {
			time.Sleep(verifyAfterUpdateDelay)
		}
		if !recordsNeedUpdate(cfg, recs, v4, v6) {
			slog.Info("post-update DNS verify succeeded")
			return nil
		}
		if attempt < maxUpdateAttempts {
			slog.Warn("post-update DNS verify failed; retrying update", "attempt", attempt)
			continue
		}
		return fmt.Errorf("DNS update not reflected in queries after %d attempts", maxUpdateAttempts)
	}
	return nil
}

// reconcile re-reads interface addresses and makes DNS match them for the given scope.
//
// If force is false, scope is dynamic/all, and the addresses equal last, it is a no-op
// (static-only passes always re-check). force is used for initial sync, timer retry,
// and pending failures.
//
// alwaysUpdate skips the "already correct" short-circuit and always sends a DNS UPDATE
// (CLI -force one-shot). Useful to refresh a last-update timestamp TXT.
//
// last is advanced only when dynamic records are in scope and the update succeeds
// (or already matches).
func reconcile(cfg *Config, ifIndex int, last *lastIPs, force bool, scope recordScope, alwaysUpdate bool) error {
	v4, v6, err := readInterfaceAddrs(ifIndex)
	if err != nil {
		return err
	}

	recs := filterRecords(cfg.Records, scope)
	if len(recs) == 0 {
		return nil
	}

	// Address-driven early exit only when we care about interface-sourced records.
	if scope != scopeStatic && !force && !alwaysUpdate && v4.Equal(last.v4) && v6.Equal(last.v6) {
		return nil
	}

	if scope != scopeStatic {
		if !v4.Equal(last.v4) {
			slog.Info("IPv4 changed", "old", last.v4, "new", v4)
		}
		if !v6.Equal(last.v6) {
			slog.Info("IPv6 changed", "old", last.v6, "new", v6)
		}
	}

	if !alwaysUpdate && !recordsNeedUpdate(cfg, recs, v4, v6) {
		if scope == scopeStatic {
			slog.Info("all static DNS records already correct")
		} else {
			slog.Info("all DNS records already match desired state")
		}
		if scope != scopeStatic {
			last.v4, last.v6 = v4, v6
		}
		return nil
	}
	if alwaysUpdate {
		slog.Info("forcing DNS UPDATE")
	}
	if err := updateAndVerify(cfg, recs, v4, v6); err != nil {
		return err
	}
	if scope != scopeStatic {
		last.v4, last.v6 = v4, v6
	}
	return nil
}

// initialSync verifies all records and updates if needed (always re-checks DNS).
// When alwaysUpdate is true, a DNS UPDATE is sent even if records already match.
func initialSync(cfg *Config, ifIndex int, last *lastIPs, alwaysUpdate bool) error {
	return reconcile(cfg, ifIndex, last, true, scopeAll, alwaysUpdate)
}

// refreshAndUpdate sends a DNS UPDATE only when interface addresses changed since last.
// Only interface-backed records are considered.
func refreshAndUpdate(cfg *Config, ifIndex int, last *lastIPs) error {
	return reconcile(cfg, ifIndex, last, false, scopeDynamic, false)
}

// stopTimer stops t and drains its channel if the timer already fired.
func stopTimer(t *time.Timer) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

// eventLoop runs the main monitor loop until stop is closed.
// On DNS failure it retries every cfg.retryInterval, re-reading addresses each time.
// Netlink address changes are applied immediately (including while a retry is pending).
// Static records are verified at start and then every cfg.staticVerifyInterval.
func eventLoop(cfg *Config, ifIndex int, addrUpdates <-chan netlink.AddrUpdate, stop <-chan struct{}) {
	last := &lastIPs{}
	pending := false // true after a failed reconcile until the next success

	var retryTimer *time.Timer
	var retryC <-chan time.Time

	scheduleRetry := func() {
		stopTimer(retryTimer)
		retryTimer = time.NewTimer(cfg.retryInterval)
		retryC = retryTimer.C
		slog.Info("scheduling DNS update retry", "after", cfg.retryInterval)
	}
	clearRetry := func() {
		stopTimer(retryTimer)
		retryTimer = nil
		retryC = nil
	}

	apply := func(force bool, scope recordScope) {
		if err := reconcile(cfg, ifIndex, last, force, scope, false); err != nil {
			slog.Error("update failed", "err", err)
			pending = true
			scheduleRetry()
			return
		}
		pending = false
		clearRetry()
	}

	// Initial sync: always verify dynamic and static records.
	apply(true, scopeAll)

	// Periodic static re-verification (only when static records exist).
	var staticTimer *time.Timer
	var staticC <-chan time.Time
	if hasStaticRecords(cfg) {
		staticTimer = time.NewTimer(cfg.staticVerifyInterval)
		staticC = staticTimer.C
		slog.Info("static record verify interval", "interval", cfg.staticVerifyInterval)
	}
	rescheduleStatic := func() {
		if staticTimer == nil {
			return
		}
		stopTimer(staticTimer)
		staticTimer = time.NewTimer(cfg.staticVerifyInterval)
		staticC = staticTimer.C
	}
	clearStatic := func() {
		stopTimer(staticTimer)
		staticTimer = nil
		staticC = nil
	}

	for {
		select {
		case update, ok := <-addrUpdates:
			if !ok {
				clearRetry()
				clearStatic()
				return
			}
			if update.LinkIndex != ifIndex {
				continue
			}
			slog.Info("address change detected", "interface", cfg.Interface)
			// If a retry is pending, force full re-attempt (dynamic + static) even
			// when addresses equal the last successful publish.
			if pending {
				apply(true, scopeAll)
			} else {
				apply(false, scopeDynamic)
			}
		case <-retryC:
			retryTimer = nil
			retryC = nil
			slog.Info("retrying DNS update")
			apply(true, scopeAll)
		case <-staticC:
			staticTimer = nil
			staticC = nil
			slog.Info("periodic static record verify")
			if err := reconcile(cfg, ifIndex, last, true, scopeStatic, false); err != nil {
				slog.Error("static update failed", "err", err)
				pending = true
				scheduleRetry()
			}
			rescheduleStatic()
		case <-stop:
			clearRetry()
			clearStatic()
			slog.Info("shutting down")
			return
		}
	}
}

func getGlobalAddrs(ifIndex int) (net.IP, net.IP, error) {
	link, err := netlink.LinkByIndex(ifIndex)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, err
	}

	var v4, v6 net.IP
	for _, a := range addrs {
		ip := a.IP
		if !ip.IsGlobalUnicast() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if v4 == nil {
				v4 = ip4
			}
		} else if v6 == nil {
			v6 = ip
		}
	}
	return v4, v6, nil
}

func performDNSUpdate(cfg *Config, recs []Record, v4, v6 net.IP) error {
	if len(recs) == 0 {
		return nil
	}
	msg := new(dns.Msg)
	msg.SetUpdate(cfg.DNS.Zone)

	for _, rec := range recs {
		rr, rdata, err := buildRR(rec, v4, v6)
		if err != nil {
			return err
		}
		// Classic dynamic update: delete RRset, then insert new record.
		msg.RemoveRRset([]dns.RR{rr})
		msg.Insert([]dns.RR{rr})
		slog.Info("will update", "name", rec.Name, "type", rec.Type, "rdata", rdata)
	}

	return exchangeDNSUpdate(cfg, msg)
}

// performDNSDelete sends a DNS UPDATE that removes records at name.
//
// If rrType is empty, all RRsets at name are deleted (RFC 2136 "delete all
// RRsets from a name"). Otherwise only the RRset of that type is deleted.
// rrType must be a known RR mnemonic when non-empty (e.g. "A", "TXT").
func performDNSDelete(cfg *Config, name, rrType string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("delete name is required")
	}
	rrType = strings.ToUpper(strings.TrimSpace(rrType))

	msg := new(dns.Msg)
	msg.SetUpdate(cfg.DNS.Zone)

	hdr := dns.RR_Header{Name: name, Class: dns.ClassINET}
	if rrType == "" {
		rr := &dns.ANY{Hdr: hdr}
		msg.RemoveName([]dns.RR{rr})
		slog.Info("will delete all records", "name", name)
	} else {
		t, ok := dns.StringToType[rrType]
		if !ok || t == dns.TypeNone {
			return fmt.Errorf("unknown RR type %q", rrType)
		}
		hdr.Rrtype = t
		rr := &dns.ANY{Hdr: hdr}
		msg.RemoveRRset([]dns.RR{rr})
		slog.Info("will delete records", "name", name, "type", rrType)
	}

	return exchangeDNSUpdate(cfg, msg)
}

// exchangeDNSUpdate sends a prepared DNS UPDATE message (optional TSIG) and
// checks for a successful reply.
func exchangeDNSUpdate(cfg *Config, msg *dns.Msg) error {
	client := &dns.Client{Net: "udp", Timeout: 10 * time.Second}
	if cfg.DNS.TSIG != nil {
		client.TsigSecret = map[string]string{cfg.DNS.TSIG.Name: cfg.DNS.TSIG.Secret}
		msg.SetTsig(cfg.DNS.TSIG.Name, mapAlgorithm(cfg.DNS.TSIG.Algorithm), 300, time.Now().Unix())
	}

	resp, _, err := client.Exchange(msg, cfg.DNS.Server)
	if err != nil {
		return fmt.Errorf("DNS exchange failed: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS update rejected: %s", dns.RcodeToString[resp.Rcode])
	}
	slog.Info("DNS UPDATE successful")
	return nil
}

func mapAlgorithm(name string) string {
	switch strings.ToLower(name) {
	case "hmac-md5", "hmac-md5.sig-alg.reg.int.":
		return dns.HmacMD5
	case "hmac-sha1":
		return dns.HmacSHA1
	case "hmac-sha224":
		return dns.HmacSHA224
	case "hmac-sha384":
		return dns.HmacSHA384
	case "hmac-sha512":
		return dns.HmacSHA512
	default:
		return dns.HmacSHA256
	}
}

func main() {
	configPath := flag.String("config", "/etc/ifnsupdate/config.yaml", "path to YAML configuration file")
	forceUpdate := flag.Bool("force", false, "force a DNS UPDATE even if records already match, then exit")
	deleteName := flag.String("delete", "", "delete DNS records for this name (one-shot), then exit")
	deleteType := flag.String("type", "", "RR type to delete with -delete (e.g. A, TXT); if empty, delete all types at the name")
	flag.Parse()

	if *deleteName != "" && *forceUpdate {
		slog.Error("-delete and -force are mutually exclusive")
		os.Exit(1)
	}
	if strings.TrimSpace(*deleteType) != "" && strings.TrimSpace(*deleteName) == "" {
		slog.Error("-type requires -delete")
		os.Exit(1)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// One-shot: delete records at a name (optional type), then exit.
	// Only dns.* from the config is required (server, zone, TSIG).
	if strings.TrimSpace(*deleteName) != "" {
		if err := validateDNSConfig(cfg); err != nil {
			slog.Error("invalid config", "err", err)
			os.Exit(1)
		}
		name, err := normalizeRecordName(*deleteName, cfg.DNS.Zone)
		if err != nil {
			slog.Error("invalid -delete name", "err", err)
			os.Exit(1)
		}
		typ := strings.ToUpper(strings.TrimSpace(*deleteType))
		if typ != "" {
			if _, ok := dns.StringToType[typ]; !ok {
				slog.Error("unknown RR type", "type", typ)
				os.Exit(1)
			}
			slog.Info("deleting DNS records", "name", name, "type", typ)
		} else {
			slog.Info("deleting all DNS records at name", "name", name)
		}
		if err := performDNSDelete(cfg, name, typ); err != nil {
			slog.Error("delete failed", "err", err)
			os.Exit(1)
		}
		slog.Info("delete complete")
		return
	}

	if err := validateConfig(cfg); err != nil {
		slog.Error("invalid config", "err", err)
		os.Exit(1)
	}

	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		slog.Error("interface not found", "interface", cfg.Interface, "err", err)
		os.Exit(1)
	}
	ifIndex := link.Attrs().Index

	// Interactive one-shot: force UPDATE for all records, then exit.
	if *forceUpdate {
		slog.Info("forcing DNS UPDATE", "interface", cfg.Interface, "index", ifIndex)
		last := &lastIPs{}
		if err := initialSync(cfg, ifIndex, last, true); err != nil {
			slog.Error("force update failed", "err", err)
			os.Exit(1)
		}
		slog.Info("force update complete")
		return
	}

	slog.Info("monitoring interface", "interface", cfg.Interface, "index", ifIndex)
	slog.Info("retry interval", "interval", cfg.retryInterval)

	updates := make(chan netlink.AddrUpdate)
	done := make(chan struct{})
	if err := netlink.AddrSubscribe(updates, done); err != nil {
		slog.Error("failed to subscribe to address updates", "err", err)
		os.Exit(1)
	}
	defer close(done)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("listening for IP address changes (Ctrl+C to stop)...")

	stop := make(chan struct{})
	go func() {
		<-sigCh
		close(stop)
	}()

	eventLoop(cfg, ifIndex, updates, stop)
}
