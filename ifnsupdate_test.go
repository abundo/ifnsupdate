package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
)

func TestMain(m *testing.M) {
	// Skip the post-update settle delay in tests.
	verifyAfterUpdateDelay = 0
	os.Exit(m.Run())
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
		check   func(t *testing.T, cfg *Config)
	}{
		{
			name:    "missing interface",
			cfg:     &Config{DNS: DNSConfig{Server: "ns:53", Zone: "ex.com."}, Records: []Record{{Name: "h.ex.com.", Type: "A"}}},
			wantErr: "interface is required",
		},
		{
			name:    "missing server",
			cfg:     &Config{Interface: "eth0", DNS: DNSConfig{Zone: "ex.com."}, Records: []Record{{Name: "h.ex.com.", Type: "A"}}},
			wantErr: "dns.server is required",
		},
		{
			name:    "missing zone",
			cfg:     &Config{Interface: "eth0", DNS: DNSConfig{Server: "ns:53"}, Records: []Record{{Name: "h.ex.com.", Type: "A"}}},
			wantErr: "dns.zone is required",
		},
		{
			name:    "no records",
			cfg:     &Config{Interface: "eth0", DNS: DNSConfig{Server: "ns:53", Zone: "ex.com."}},
			wantErr: "at least one record is required",
		},
		{
			name: "bad record type",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "ex.com."},
				Records:   []Record{{Name: "h.ex.com.", Type: "MX"}},
			},
			wantErr: "must be A, AAAA, CNAME, or TXT",
		},
		{
			name: "CNAME without value",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "ex.com."},
				Records:   []Record{{Name: "www", Type: "CNAME"}},
			},
			wantErr: "value is required for CNAME",
		},
		{
			name: "TXT without value",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "ex.com."},
				Records:   []Record{{Name: "h", Type: "TXT"}},
			},
			wantErr: "value is required for TXT",
		},
		{
			name: "static A with bad IP",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "ex.com."},
				Records:   []Record{{Name: "h", Type: "A", Value: "not-an-ip"}},
			},
			wantErr: "not a valid IP",
		},
		{
			name: "static A with IPv6",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "ex.com."},
				Records:   []Record{{Name: "h", Type: "A", Value: "2001:db8::1"}},
			},
			wantErr: "must be an IPv4",
		},
		{
			name: "static AAAA with IPv4",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "ex.com."},
				Records:   []Record{{Name: "h", Type: "AAAA", Value: "192.0.2.1"}},
			},
			wantErr: "must be an IPv6",
		},
		{
			name: "bad retry_interval",
			cfg: &Config{
				Interface:     "eth0",
				DNS:           DNSConfig{Server: "ns:53", Zone: "ex.com."},
				Records:       []Record{{Name: "h.ex.com.", Type: "A"}},
				RetryInterval: "nope",
			},
			wantErr: "retry_interval",
		},
		{
			name: "zero static_verify_interval",
			cfg: &Config{
				Interface:            "eth0",
				DNS:                  DNSConfig{Server: "ns:53", Zone: "ex.com."},
				Records:              []Record{{Name: "h.ex.com.", Type: "A"}},
				StaticVerifyInterval: "0s",
			},
			wantErr: "static_verify_interval must be positive",
		},
		{
			name: "tsig incomplete",
			cfg: &Config{
				Interface: "eth0",
				DNS: DNSConfig{
					Server: "ns:53",
					Zone:   "ex.com.",
					TSIG:   &TSIGConfig{Name: "key."},
				},
				Records: []Record{{Name: "h.ex.com.", Type: "A"}},
			},
			wantErr: "tsig.name and tsig.secret",
		},
		{
			name: "normalizes FQDNs and defaults",
			cfg: &Config{
				Interface: "eth0",
				DNS: DNSConfig{
					Server: "ns:53",
					Zone:   "example.com",
					TSIG: &TSIGConfig{
						Name:   "ifnsupdate-key.example.com",
						Secret: "c2VjcmV0",
					},
				},
				Records: []Record{
					{Name: "host.example.com", Type: "a"},
				},
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.DNS.Zone != "example.com." {
					t.Errorf("zone = %q, want trailing dot", cfg.DNS.Zone)
				}
				if cfg.DNS.TSIG.Name != "ifnsupdate-key.example.com." {
					t.Errorf("tsig name = %q", cfg.DNS.TSIG.Name)
				}
				if cfg.DNS.TSIG.Algorithm != "hmac-sha256" {
					t.Errorf("algorithm default = %q", cfg.DNS.TSIG.Algorithm)
				}
				if cfg.Records[0].Name != "host.example.com." {
					t.Errorf("record name = %q", cfg.Records[0].Name)
				}
				if cfg.Records[0].Type != "A" {
					t.Errorf("record type = %q", cfg.Records[0].Type)
				}
				if cfg.Records[0].TTL != 300 {
					t.Errorf("ttl default = %d", cfg.Records[0].TTL)
				}
				if cfg.retryInterval != defaultRetryInterval {
					t.Errorf("retryInterval default = %v", cfg.retryInterval)
				}
				if cfg.staticVerifyInterval != defaultStaticVerifyInterval {
					t.Errorf("staticVerifyInterval default = %v", cfg.staticVerifyInterval)
				}
			},
		},
		{
			name: "parses intervals and static records",
			cfg: &Config{
				Interface:            "eth0",
				DNS:                  DNSConfig{Server: "ns:53", Zone: "example.com."},
				RetryInterval:        "2m",
				StaticVerifyInterval: "30m",
				Records: []Record{
					{Name: "myhost", Type: "A"},
					{Name: "fixed", Type: "A", Value: "192.0.2.1"},
					{Name: "fixed", Type: "AAAA", Value: "2001:db8::1"},
					{Name: "www", Type: "CNAME", Value: "myhost"},
					{Name: "myhost", Type: "TXT", Value: "hello world"},
					{Name: "alias", Type: "CNAME", Value: "other.org."},
				},
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.retryInterval != 2*time.Minute {
					t.Errorf("retryInterval = %v", cfg.retryInterval)
				}
				if cfg.staticVerifyInterval != 30*time.Minute {
					t.Errorf("staticVerifyInterval = %v", cfg.staticVerifyInterval)
				}
				if cfg.Records[0].isStatic() {
					t.Error("interface A should not be static")
				}
				if !cfg.Records[1].isStatic() || cfg.Records[1].Value != "192.0.2.1" {
					t.Errorf("static A = %+v", cfg.Records[1])
				}
				if cfg.Records[3].Value != "myhost.example.com." {
					t.Errorf("CNAME target = %q", cfg.Records[3].Value)
				}
				if cfg.Records[5].Value != "other.org." {
					t.Errorf("external CNAME = %q", cfg.Records[5].Value)
				}
				if cfg.Records[4].Value != "hello world" {
					t.Errorf("TXT = %q", cfg.Records[4].Value)
				}
			},
		},
		{
			name: "relative name gets zone appended",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "example.com."},
				Records:   []Record{{Name: "myhost", Type: "A"}},
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Records[0].Name != "myhost.example.com." {
					t.Errorf("record name = %q", cfg.Records[0].Name)
				}
			},
		},
		{
			name: "nested relative name",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "example.com."},
				Records:   []Record{{Name: "vpn.myhost", Type: "AAAA"}},
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Records[0].Name != "vpn.myhost.example.com." {
					t.Errorf("record name = %q", cfg.Records[0].Name)
				}
			},
		},
		{
			name: "apex via @",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "example.com."},
				Records:   []Record{{Name: "@", Type: "A"}},
			},
			check: func(t *testing.T, cfg *Config) {
				if cfg.Records[0].Name != "example.com." {
					t.Errorf("record name = %q", cfg.Records[0].Name)
				}
			},
		},
		{
			name: "empty name",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "example.com."},
				Records:   []Record{{Name: "", Type: "A"}},
			},
			wantErr: "name is required",
		},
		{
			name: "absolute name outside zone",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "example.com."},
				Records:   []Record{{Name: "other.org.", Type: "A"}},
			},
			wantErr: "is not in zone",
		},
		{
			name: "suffix trap notexample.com is out of zone",
			cfg: &Config{
				Interface: "eth0",
				DNS:       DNSConfig{Server: "ns:53", Zone: "example.com."},
				Records:   []Record{{Name: "notexample.com.", Type: "A"}},
			},
			wantErr: "is not in zone",
		},
	}

	// Also exercise nameInZone / normalizeRecordName directly for edge cases.
	t.Run("normalizeRecordName", func(t *testing.T) {
		t.Parallel()
		zone := "example.com."
		cases := []struct {
			in, want string
			wantErr  string
		}{
			{"host", "host.example.com.", ""},
			{"HOST", "HOST.example.com.", ""},
			{"host.example.com", "host.example.com.", ""},
			{"host.example.com.", "host.example.com.", ""},
			{"Host.Example.COM.", "Host.Example.COM.", ""},
			{"@", "example.com.", ""},
			{"example.com.", "example.com.", ""},
			{"sub.host.example.com.", "sub.host.example.com.", ""},
			{"evil.org.", "", "is not in zone"},
			{"", "", "is required"},
		}
		for _, c := range cases {
			got, err := normalizeRecordName(c.in, zone)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("normalizeRecordName(%q): err=%v, want containing %q", c.in, err, c.wantErr)
				}
				continue
			}
			if err != nil {
				t.Errorf("normalizeRecordName(%q): unexpected err %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("normalizeRecordName(%q) = %q, want %q", c.in, got, c.want)
			}
		}
		if nameInZone("notexample.com.", zone) {
			t.Error("notexample.com. must not be in example.com.")
		}
		if !nameInZone("a.example.com.", zone) || !nameInZone("example.com.", zone) {
			t.Error("expected in-zone names")
		}
	})

	t.Run("normalizeCNAMETarget", func(t *testing.T) {
		t.Parallel()
		zone := "example.com."
		cases := []struct {
			in, want string
		}{
			{"myhost", "myhost.example.com."},
			{"myhost.example.com", "myhost.example.com."},
			{"other.org.", "other.org."},
			{"@", "example.com."},
		}
		for _, c := range cases {
			got, err := normalizeCNAMETarget(c.in, zone)
			if err != nil {
				t.Errorf("normalizeCNAMETarget(%q): %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("normalizeCNAMETarget(%q) = %q, want %q", c.in, got, c.want)
			}
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfig(tt.cfg)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, tt.cfg)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	content := `
interface: eth0
retry_interval: 1m
static_verify_interval: 15m
dns:
  server: "127.0.0.1:53"
  zone: "example.com."
records:
  - name: "host.example.com."
    type: A
    ttl: 60
  - name: www
    type: CNAME
    value: host
  - name: host
    type: TXT
    value: "v=spf1 -all"
  - name: fixed
    type: A
    value: "192.0.2.9"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Interface != "eth0" {
		t.Errorf("interface = %q", cfg.Interface)
	}
	if cfg.DNS.Server != "127.0.0.1:53" {
		t.Errorf("server = %q", cfg.DNS.Server)
	}
	if cfg.retryInterval != time.Minute || cfg.staticVerifyInterval != 15*time.Minute {
		t.Errorf("intervals = %v %v", cfg.retryInterval, cfg.staticVerifyInterval)
	}
	if len(cfg.Records) != 4 {
		t.Fatalf("records = %+v", cfg.Records)
	}
	if cfg.Records[1].Type != "CNAME" || cfg.Records[1].Value != "host.example.com." {
		t.Errorf("CNAME = %+v", cfg.Records[1])
	}
	if cfg.Records[3].Value != "192.0.2.9" || !cfg.Records[3].isStatic() {
		t.Errorf("static A = %+v", cfg.Records[3])
	}

	if _, err := loadConfig(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestMapAlgorithm(t *testing.T) {
	t.Parallel()
	if mapAlgorithm("hmac-sha256") != dns.HmacSHA256 {
		t.Fatal("sha256")
	}
	if mapAlgorithm("hmac-sha1") != dns.HmacSHA1 {
		t.Fatal("sha1")
	}
	if mapAlgorithm("unknown") != dns.HmacSHA256 {
		t.Fatal("default")
	}
}

func startMockDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	server := &dns.Server{
		Net: "udp",
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction {
			return dns.MsgAccept
		},
		Handler: handler,
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.PacketConn = pc
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	time.Sleep(20 * time.Millisecond)
	return pc.LocalAddr().String()
}

func TestQueryRecordIPs(t *testing.T) {
	v4 := net.ParseIP("192.0.2.50").To4()
	v6 := net.ParseIP("2001:db8::50")
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   v4,
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: v6,
			})
		}
		_ = w.WriteMsg(m)
	})

	cfg := &Config{DNS: DNSConfig{Server: addr}}
	got4, err := queryRecordIPs(cfg, "host.example.com.", "A")
	if err != nil {
		t.Fatal(err)
	}
	if len(got4) != 1 || !got4[0].Equal(v4) {
		t.Fatalf("A answers = %v, want [%v]", got4, v4)
	}
	got6, err := queryRecordIPs(cfg, "host.example.com.", "AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if len(got6) != 1 || !got6[0].Equal(v6) {
		t.Fatalf("AAAA answers = %v, want [%v]", got6, v6)
	}
}

func TestQueryRecordIPsNXDOMAIN(t *testing.T) {
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})
	cfg := &Config{DNS: DNSConfig{Server: addr}}
	got, err := queryRecordIPs(cfg, "missing.example.com.", "A")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty answers, got %v", got)
	}
}

func TestRecordMatches(t *testing.T) {
	v4 := net.ParseIP("192.0.2.10").To4()
	cnameTarget := "host.example.com."
	txtVal := "hello world"
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   v4,
			})
		case dns.TypeCNAME:
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: cnameTarget,
			})
		case dns.TypeTXT:
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{txtVal},
			})
		}
		_ = w.WriteMsg(m)
	})
	cfg := &Config{DNS: DNSConfig{Server: addr}}

	ok, err := recordMatches(cfg, Record{Name: "host.example.com.", Type: "A", TTL: 60}, v4, nil)
	if err != nil || !ok {
		t.Fatalf("expected A match, ok=%v err=%v", ok, err)
	}
	ok, err = recordMatches(cfg, Record{Name: "host.example.com.", Type: "A", TTL: 60}, net.ParseIP("192.0.2.99").To4(), nil)
	if err != nil || ok {
		t.Fatalf("expected A mismatch, ok=%v err=%v", ok, err)
	}

	ok, err = recordMatches(cfg, Record{Name: "www.example.com.", Type: "CNAME", Value: cnameTarget}, nil, nil)
	if err != nil || !ok {
		t.Fatalf("expected CNAME match, ok=%v err=%v", ok, err)
	}
	ok, err = recordMatches(cfg, Record{Name: "www.example.com.", Type: "CNAME", Value: "other.example.com."}, nil, nil)
	if err != nil || ok {
		t.Fatalf("expected CNAME mismatch, ok=%v err=%v", ok, err)
	}

	ok, err = recordMatches(cfg, Record{Name: "host.example.com.", Type: "TXT", Value: txtVal}, nil, nil)
	if err != nil || !ok {
		t.Fatalf("expected TXT match, ok=%v err=%v", ok, err)
	}
	ok, err = recordMatches(cfg, Record{Name: "host.example.com.", Type: "TXT", Value: "nope"}, nil, nil)
	if err != nil || ok {
		t.Fatalf("expected TXT mismatch, ok=%v err=%v", ok, err)
	}

	// Static A uses value, not interface IP.
	ok, err = recordMatches(cfg, Record{Name: "host.example.com.", Type: "A", Value: "192.0.2.10"}, nil, nil)
	if err != nil || !ok {
		t.Fatalf("expected static A match, ok=%v err=%v", ok, err)
	}
}

func TestRecordsNeedUpdate(t *testing.T) {
	correct := net.ParseIP("192.0.2.10").To4()
	wrong := net.ParseIP("192.0.2.99").To4()
	var answer atomic.Pointer[net.IP]
	// store as copy via heap pointer
	ip := correct
	answer.Store(&ip)

	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if p := answer.Load(); p != nil && *p != nil && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   (*p).To4(),
			})
		}
		_ = w.WriteMsg(m)
	})

	recs := []Record{{Name: "host.example.com.", Type: "A", TTL: 60}}
	cfg := &Config{
		DNS:     DNSConfig{Server: addr, Zone: "example.com."},
		Records: recs,
	}

	if recordsNeedUpdate(cfg, recs, correct, nil) {
		t.Fatal("should not need update when DNS matches")
	}
	w := wrong
	answer.Store(&w)
	if !recordsNeedUpdate(cfg, recs, correct, nil) {
		t.Fatal("should need update when DNS differs")
	}
	// Empty answer (no A RR) → needs update
	var none net.IP
	answer.Store(&none)
	if !recordsNeedUpdate(cfg, recs, correct, nil) {
		t.Fatal("should need update when record is missing")
	}
	// No local IP for A → needs update (will fail at performDNSUpdate)
	if !recordsNeedUpdate(cfg, recs, nil, nil) {
		t.Fatal("should need update when no local addresses")
	}
}

func TestInitialSyncErrorsWhenNoAddress(t *testing.T) {
	var updates atomic.Int32
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skip(err)
	}
	// lo has no global addrs; configured A record cannot be published.
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeUpdate {
			updates.Add(1)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess
		_ = w.WriteMsg(m)
	})
	cfg := &Config{
		Interface: "lo",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records:   []Record{{Name: "h.example.com.", Type: "A", TTL: 60}},
	}
	_ = validateConfig(cfg)
	last := &lastIPs{}
	if err := initialSync(cfg, link.Attrs().Index, last); err == nil {
		t.Fatal("expected error when interface has no address for configured record")
	}
	if updates.Load() != 0 {
		t.Fatalf("expected no UPDATE when no addresses, got %d", updates.Load())
	}
	if last.v4 != nil || last.v6 != nil {
		t.Fatalf("last should stay nil on lo, got %v %v", last.v4, last.v6)
	}
}

func TestInitialSyncUpdatesWhenIncorrect(t *testing.T) {
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		t.Skip(err)
	}
	v4, v6, err := getGlobalAddrs(link.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	if v4 == nil && v6 == nil {
		t.Skip("eth0 has no global addresses")
	}

	var updates atomic.Int32
	// Before UPDATE, queries return empty (need update). After UPDATE, return the
	// interface addresses so post-update verify succeeds.
	var published atomic.Bool
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			updates.Add(1)
			published.Store(true)
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeSuccess
		if published.Load() && len(r.Question) > 0 {
			q := r.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				if v4 != nil {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   v4,
					})
				}
			case dns.TypeAAAA:
				if v6 != nil {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: v6,
					})
				}
			}
		}
		_ = w.WriteMsg(m)
	})

	recs := []Record{}
	if v4 != nil {
		recs = append(recs, Record{Name: "h.example.com.", Type: "A", TTL: 60})
	}
	if v6 != nil {
		recs = append(recs, Record{Name: "h.example.com.", Type: "AAAA", TTL: 60})
	}
	cfg := &Config{
		Interface: "eth0",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records:   recs,
	}
	_ = validateConfig(cfg)
	last := &lastIPs{}
	if err := initialSync(cfg, link.Attrs().Index, last); err != nil {
		t.Fatal(err)
	}
	if updates.Load() != 1 {
		t.Fatalf("expected 1 UPDATE after failed pre-check, got %d", updates.Load())
	}
	if !last.v4.Equal(v4) || !last.v6.Equal(v6) {
		t.Fatalf("last = %v %v, want %v %v", last.v4, last.v6, v4, v6)
	}
}

func TestInitialSyncNoUpdateWhenAlreadyCorrect(t *testing.T) {
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		t.Skip(err)
	}
	v4, _, err := getGlobalAddrs(link.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	if v4 == nil {
		t.Skip("eth0 has no global IPv4")
	}

	var updates atomic.Int32
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			updates.Add(1)
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   v4,
			})
		}
		_ = w.WriteMsg(m)
	})

	cfg := &Config{
		Interface: "eth0",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records:   []Record{{Name: "h.example.com.", Type: "A", TTL: 60}},
	}
	_ = validateConfig(cfg)
	last := &lastIPs{}
	if err := initialSync(cfg, link.Attrs().Index, last); err != nil {
		t.Fatal(err)
	}
	if updates.Load() != 0 {
		t.Fatalf("expected no UPDATE when DNS already correct, got %d", updates.Load())
	}
	if !last.v4.Equal(v4) {
		t.Fatalf("last.v4 = %v, want %v", last.v4, v4)
	}
}

func TestInitialSyncStaticRecords(t *testing.T) {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skip(err)
	}

	staticIP := net.ParseIP("192.0.2.50").To4()
	cnameTarget := "target.example.com."
	txtVal := "static-txt"

	var (
		updates   atomic.Int32
		published atomic.Bool
		mu        sync.Mutex
		ns        []dns.RR
	)
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			updates.Add(1)
			published.Store(true)
			mu.Lock()
			ns = append([]dns.RR(nil), r.Ns...)
			mu.Unlock()
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeSuccess
		if published.Load() && len(r.Question) > 0 {
			q := r.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   staticIP,
				})
			case dns.TypeCNAME:
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
					Target: cnameTarget,
				})
			case dns.TypeTXT:
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{txtVal},
				})
			}
		}
		_ = w.WriteMsg(m)
	})

	cfg := &Config{
		Interface: "lo",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records: []Record{
			{Name: "fixed.example.com.", Type: "A", Value: "192.0.2.50", TTL: 60},
			{Name: "www.example.com.", Type: "CNAME", Value: cnameTarget, TTL: 60},
			{Name: "txt.example.com.", Type: "TXT", Value: txtVal, TTL: 60},
		},
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	last := &lastIPs{}
	if err := initialSync(cfg, link.Attrs().Index, last); err != nil {
		t.Fatal(err)
	}
	if updates.Load() != 1 {
		t.Fatalf("expected 1 UPDATE for static records, got %d", updates.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	var sawA, sawCNAME, sawTXT bool
	for _, rr := range ns {
		switch r := rr.(type) {
		case *dns.A:
			if r.A.Equal(staticIP) {
				sawA = true
			}
		case *dns.CNAME:
			if strings.EqualFold(r.Target, cnameTarget) {
				sawCNAME = true
			}
		case *dns.TXT:
			if strings.Join(r.Txt, "") == txtVal {
				sawTXT = true
			}
		}
	}
	if !sawA || !sawCNAME || !sawTXT {
		t.Fatalf("missing inserts A=%v CNAME=%v TXT=%v; ns=%v", sawA, sawCNAME, sawTXT, ns)
	}
}

func TestPerformDNSUpdateAgainstMockServer(t *testing.T) {
	var (
		mu       sync.Mutex
		received []*dns.Msg
	)
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		mu.Lock()
		received = append(received, r.Copy())
		mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess
		_ = w.WriteMsg(m)
	})

	recs := []Record{
		{Name: "host.example.com.", Type: "A", TTL: 300},
		{Name: "host.example.com.", Type: "AAAA", TTL: 300},
		{Name: "www.example.com.", Type: "CNAME", Value: "host.example.com.", TTL: 300},
		{Name: "host.example.com.", Type: "TXT", Value: "v=spf1 -all", TTL: 300},
		{Name: "fixed.example.com.", Type: "A", Value: "192.0.2.99", TTL: 300},
	}
	cfg := &Config{
		DNS:     DNSConfig{Server: addr, Zone: "example.com."},
		Records: recs,
	}
	v4 := net.ParseIP("192.0.2.10").To4()
	v6 := net.ParseIP("2001:db8::10")

	if err := performDNSUpdate(cfg, recs, v4, v6); err != nil {
		t.Fatalf("performDNSUpdate: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 update message, got %d", len(received))
	}
	msg := received[0]
	if msg.Opcode != dns.OpcodeUpdate {
		t.Fatalf("message is not an UPDATE (opcode=%d)", msg.Opcode)
	}
	if msg.Question[0].Name != "example.com." {
		t.Errorf("zone question = %q", msg.Question[0].Name)
	}

	var sawA, sawAAAA, sawCNAME, sawTXT, sawStaticA bool
	for _, rr := range msg.Ns {
		switch r := rr.(type) {
		case *dns.A:
			if r.A.Equal(v4) {
				sawA = true
			}
			if r.A.Equal(net.ParseIP("192.0.2.99").To4()) {
				sawStaticA = true
			}
		case *dns.AAAA:
			if r.AAAA.Equal(v6) {
				sawAAAA = true
			}
		case *dns.CNAME:
			if strings.EqualFold(r.Target, "host.example.com.") {
				sawCNAME = true
			}
		case *dns.TXT:
			if strings.Join(r.Txt, "") == "v=spf1 -all" {
				sawTXT = true
			}
		}
	}
	if !sawA || !sawAAAA || !sawCNAME || !sawTXT || !sawStaticA {
		t.Fatalf("missing insert RRs: A=%v AAAA=%v CNAME=%v TXT=%v staticA=%v; ns=%v",
			sawA, sawAAAA, sawCNAME, sawTXT, sawStaticA, msg.Ns)
	}
}

func TestPerformDNSUpdateRequiresAddress(t *testing.T) {
	var received atomic.Int32
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		received.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess
		_ = w.WriteMsg(m)
	})

	recs := []Record{
		{Name: "host.example.com.", Type: "A", TTL: 60},
		{Name: "host.example.com.", Type: "AAAA", TTL: 60},
	}
	cfg := &Config{
		DNS:     DNSConfig{Server: addr, Zone: "example.com."},
		Records: recs,
	}

	err := performDNSUpdate(cfg, recs, net.ParseIP("192.0.2.1").To4(), nil)
	if err == nil || !strings.Contains(err.Error(), "no AAAA address") {
		t.Fatalf("expected missing AAAA error, got %v", err)
	}
	if received.Load() != 0 {
		t.Fatalf("expected no DNS exchange when family missing, got %d", received.Load())
	}

	err = performDNSUpdate(cfg, recs, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no A address") {
		t.Fatalf("expected missing A error, got %v", err)
	}
	if received.Load() != 0 {
		t.Fatalf("expected no DNS exchange when no IPs, got %d", received.Load())
	}
}

func TestPerformDNSUpdateRejectsRcode(t *testing.T) {
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
	})

	recs := []Record{{Name: "h.example.com.", Type: "A", TTL: 60}}
	cfg := &Config{
		DNS:     DNSConfig{Server: addr, Zone: "example.com."},
		Records: recs,
	}
	err := performDNSUpdate(cfg, recs, net.ParseIP("192.0.2.1").To4(), nil)
	if err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("expected REFUSED error, got %v", err)
	}
}

func TestGetGlobalAddrsOnLoopback(t *testing.T) {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skipf("lo not available: %v", err)
	}
	v4, v6, err := getGlobalAddrs(link.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	if v4 != nil || v6 != nil {
		t.Fatalf("loopback should yield no global addrs, got v4=%v v6=%v", v4, v6)
	}
}

func TestRefreshAndUpdateOnlyOnChange(t *testing.T) {
	var received atomic.Int32
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		received.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess
		_ = w.WriteMsg(m)
	})

	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Skip(err)
	}
	cfg := &Config{
		Interface: "lo",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records:   []Record{{Name: "h.example.com.", Type: "A", TTL: 60}},
	}
	_ = validateConfig(cfg)
	last := &lastIPs{}

	// nil→nil is not a change.
	if err := refreshAndUpdate(cfg, link.Attrs().Index, last); err != nil {
		t.Fatal(err)
	}
	if received.Load() != 0 {
		t.Fatalf("nil→nil should not update DNS, received=%d", received.Load())
	}

	// Seed a previous IPv4; lo still has none → change detected, update fails (no A address).
	last.v4 = net.ParseIP("192.0.2.1").To4()
	if err := refreshAndUpdate(cfg, link.Attrs().Index, last); err == nil {
		t.Fatal("expected error when address disappears and A cannot be published")
	}
	if received.Load() != 0 {
		t.Fatalf("expected no DNS exchange when no IP for A, got %d", received.Load())
	}
	// Cache must not advance on failure so the next attempt can retry.
	if !last.v4.Equal(net.ParseIP("192.0.2.1").To4()) || last.v6 != nil {
		t.Fatalf("cache should stay at old value after failure, got %v %v", last.v4, last.v6)
	}
}

func TestFailedUpdateAllowsRetry(t *testing.T) {
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		t.Skip(err)
	}
	v4, v6, err := getGlobalAddrs(link.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	if v4 == nil && v6 == nil {
		t.Skip("eth0 has no global addresses")
	}

	var updateCalls atomic.Int32
	var published atomic.Bool
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			n := updateCalls.Add(1)
			if n == 1 {
				m.Rcode = dns.RcodeServerFailure
			} else {
				m.Rcode = dns.RcodeSuccess
				published.Store(true)
			}
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeSuccess
		if published.Load() && len(r.Question) > 0 {
			q := r.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				if v4 != nil {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   v4,
					})
				}
			case dns.TypeAAAA:
				if v6 != nil {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: v6,
					})
				}
			}
		}
		_ = w.WriteMsg(m)
	})

	// Only configure record types for address families present on the interface.
	// Otherwise buildRR fails with "no AAAA address" before any UPDATE is sent
	// (common on CI runners that only have IPv4).
	recs := []Record{}
	if v4 != nil {
		recs = append(recs, Record{Name: "h.example.com.", Type: "A", TTL: 60})
	}
	if v6 != nil {
		recs = append(recs, Record{Name: "h.example.com.", Type: "AAAA", TTL: 60})
	}
	cfg := &Config{
		Interface: "eth0",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records:   recs,
	}
	_ = validateConfig(cfg)
	last := &lastIPs{}

	if err := refreshAndUpdate(cfg, link.Attrs().Index, last); err == nil {
		t.Fatal("expected DNS failure on first attempt")
	}
	if updateCalls.Load() != 1 {
		t.Fatalf("updateCalls=%d want 1", updateCalls.Load())
	}
	if last.v4 != nil || last.v6 != nil {
		t.Fatalf("cache should be empty after failure, got %v %v", last.v4, last.v6)
	}

	if err := refreshAndUpdate(cfg, link.Attrs().Index, last); err != nil {
		t.Fatalf("second attempt should succeed: %v", err)
	}
	if updateCalls.Load() != 2 {
		t.Fatalf("expected retry after failed update; updateCalls=%d", updateCalls.Load())
	}
}

func TestUpdateAndVerifyRetriesWhenNotVisible(t *testing.T) {
	v4 := net.ParseIP("192.0.2.10").To4()
	var updates atomic.Int32
	// Queries always return empty so post-update verify keeps failing.
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			updates.Add(1)
		}
		m.Rcode = dns.RcodeSuccess
		_ = w.WriteMsg(m)
	})

	recs := []Record{{Name: "h.example.com.", Type: "A", TTL: 60}}
	cfg := &Config{
		DNS:     DNSConfig{Server: addr, Zone: "example.com."},
		Records: recs,
	}
	err := updateAndVerify(cfg, recs, v4, nil)
	if err == nil {
		t.Fatal("expected error when update never becomes visible")
	}
	if !strings.Contains(err.Error(), "not reflected") {
		t.Fatalf("unexpected error: %v", err)
	}
	if updates.Load() != int32(maxUpdateAttempts) {
		t.Fatalf("expected %d UPDATEs, got %d", maxUpdateAttempts, updates.Load())
	}
}

func TestUpdateAndVerifySucceedsOnSecondAttempt(t *testing.T) {
	v4 := net.ParseIP("192.0.2.10").To4()
	var updates atomic.Int32
	// First post-update query returns wrong; after second UPDATE, return correct.
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			updates.Add(1)
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeSuccess
		// Only answer correctly after the second UPDATE.
		if updates.Load() >= 2 && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   v4,
			})
		}
		_ = w.WriteMsg(m)
	})

	recs := []Record{{Name: "h.example.com.", Type: "A", TTL: 60}}
	cfg := &Config{
		DNS:     DNSConfig{Server: addr, Zone: "example.com."},
		Records: recs,
	}
	if err := updateAndVerify(cfg, recs, v4, nil); err != nil {
		t.Fatalf("expected success on retry: %v", err)
	}
	if updates.Load() != 2 {
		t.Fatalf("expected 2 UPDATEs, got %d", updates.Load())
	}
}

func TestUpdateAndVerifySucceedsFirstAttempt(t *testing.T) {
	v4 := net.ParseIP("192.0.2.10").To4()
	var updates atomic.Int32
	var published atomic.Bool
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			updates.Add(1)
			published.Store(true)
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeSuccess
		if published.Load() && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   v4,
			})
		}
		_ = w.WriteMsg(m)
	})

	recs := []Record{{Name: "h.example.com.", Type: "A", TTL: 60}}
	cfg := &Config{
		DNS:     DNSConfig{Server: addr, Zone: "example.com."},
		Records: recs,
	}
	if err := updateAndVerify(cfg, recs, v4, nil); err != nil {
		t.Fatal(err)
	}
	if updates.Load() != 1 {
		t.Fatalf("expected 1 UPDATE, got %d", updates.Load())
	}
}

func TestEventLoopRetriesFailedUpdate(t *testing.T) {
	oldRead := readInterfaceAddrs
	t.Cleanup(func() {
		readInterfaceAddrs = oldRead
	})

	v4 := net.ParseIP("192.0.2.10").To4()
	readInterfaceAddrs = func(int) (net.IP, net.IP, error) {
		return v4, nil, nil
	}

	var updateCalls atomic.Int32
	var published atomic.Bool
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			n := updateCalls.Add(1)
			if n == 1 {
				m.Rcode = dns.RcodeServerFailure
			} else {
				m.Rcode = dns.RcodeSuccess
				published.Store(true)
			}
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeSuccess
		if published.Load() && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   v4,
			})
		}
		_ = w.WriteMsg(m)
	})

	cfg := &Config{
		Interface: "eth0",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records:   []Record{{Name: "h.example.com.", Type: "A", TTL: 60}},
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.retryInterval = 40 * time.Millisecond

	addrUpdates := make(chan netlink.AddrUpdate)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		eventLoop(cfg, 1, addrUpdates, stop)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for updateCalls.Load() < 2 || !published.Load() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for retry; updates=%d published=%v", updateCalls.Load(), published.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("eventLoop did not exit")
	}
}

func TestEventLoopAppliesAddressChangeDuringRetry(t *testing.T) {
	oldRead := readInterfaceAddrs
	t.Cleanup(func() {
		readInterfaceAddrs = oldRead
	})

	ipA := net.ParseIP("192.0.2.10").To4()
	ipB := net.ParseIP("192.0.2.20").To4()
	var current atomic.Pointer[net.IP]
	current.Store(&ipA)

	readInterfaceAddrs = func(int) (net.IP, net.IP, error) {
		p := current.Load()
		return (*p).To4(), nil, nil
	}

	var (
		mu            sync.Mutex
		updateIPs     []net.IP
		allowSuccess  atomic.Bool
		publishedAddr atomic.Pointer[net.IP] // last successfully UPDATEd A
	)
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			// Capture the A insert from the UPDATE.
			var got net.IP
			for _, rr := range r.Ns {
				if a, ok := rr.(*dns.A); ok {
					got = a.A
				}
			}
			mu.Lock()
			if got != nil {
				updateIPs = append(updateIPs, append(net.IP(nil), got...))
			}
			mu.Unlock()

			if !allowSuccess.Load() {
				m.Rcode = dns.RcodeServerFailure
				_ = w.WriteMsg(m)
				return
			}
			if got != nil {
				ip := append(net.IP(nil), got...)
				publishedAddr.Store(&ip)
			}
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeSuccess
		// Answer only with what was actually published (so pre-check still needs UPDATE).
		if p := publishedAddr.Load(); p != nil && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   (*p).To4(),
			})
		}
		_ = w.WriteMsg(m)
	})

	cfg := &Config{
		Interface: "eth0",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records:   []Record{{Name: "h.example.com.", Type: "A", TTL: 60}},
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	// Long interval so the timer does not race with the address-change path.
	cfg.retryInterval = time.Hour

	const ifIndex = 42
	addrUpdates := make(chan netlink.AddrUpdate, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		eventLoop(cfg, ifIndex, addrUpdates, stop)
		close(done)
	}()

	// Wait until initial sync has failed at least once with ipA.
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(updateIPs)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for initial failed UPDATE")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Interface address changes while a retry is pending; next attempt must use ipB.
	current.Store(&ipB)
	allowSuccess.Store(true)
	addrUpdates <- netlink.AddrUpdate{LinkIndex: ifIndex}

	deadline = time.After(2 * time.Second)
	for {
		mu.Lock()
		sawB := false
		for _, ip := range updateIPs {
			if ip.Equal(ipB) {
				sawB = true
				break
			}
		}
		mu.Unlock()
		if sawB {
			break
		}
		select {
		case <-deadline:
			mu.Lock()
			t.Fatalf("timed out waiting for UPDATE with new address; saw %v", updateIPs)
			mu.Unlock()
		case <-time.After(10 * time.Millisecond):
		}
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("eventLoop did not exit")
	}
}

func TestEventLoopStaticVerifyInterval(t *testing.T) {
	oldRead := readInterfaceAddrs
	t.Cleanup(func() {
		readInterfaceAddrs = oldRead
	})
	readInterfaceAddrs = func(int) (net.IP, net.IP, error) {
		return nil, nil, nil
	}

	staticIP := net.ParseIP("192.0.2.50").To4()
	var (
		updates      atomic.Int32
		serveCorrect atomic.Bool
	)
	addr := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Opcode == dns.OpcodeUpdate {
			updates.Add(1)
			serveCorrect.Store(true)
			m.Rcode = dns.RcodeSuccess
			_ = w.WriteMsg(m)
			return
		}
		m.Rcode = dns.RcodeSuccess
		if serveCorrect.Load() && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   staticIP,
			})
		}
		_ = w.WriteMsg(m)
	})

	cfg := &Config{
		Interface: "eth0",
		DNS:       DNSConfig{Server: addr, Zone: "example.com."},
		Records: []Record{
			{Name: "fixed.example.com.", Type: "A", Value: "192.0.2.50", TTL: 60},
		},
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.staticVerifyInterval = 40 * time.Millisecond
	cfg.retryInterval = time.Hour

	addrUpdates := make(chan netlink.AddrUpdate)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		eventLoop(cfg, 1, addrUpdates, stop)
		close(done)
	}()

	// Wait for initial sync to publish static A.
	deadline := time.After(2 * time.Second)
	for updates.Load() < 1 {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for initial static UPDATE; updates=%d", updates.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Simulate zone drift so the next periodic verify must re-publish.
	serveCorrect.Store(false)

	deadline = time.After(2 * time.Second)
	for updates.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for periodic static verify; updates=%d", updates.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("eventLoop did not exit")
	}
}

func TestFilterRecords(t *testing.T) {
	t.Parallel()
	recs := []Record{
		{Name: "a.", Type: "A"},
		{Name: "b.", Type: "A", Value: "192.0.2.1"},
		{Name: "c.", Type: "CNAME", Value: "a."},
		{Name: "d.", Type: "TXT", Value: "x"},
		{Name: "e.", Type: "AAAA"},
	}
	dyn := filterRecords(recs, scopeDynamic)
	if len(dyn) != 2 || dyn[0].Name != "a." || dyn[1].Name != "e." {
		t.Fatalf("dynamic = %+v", dyn)
	}
	st := filterRecords(recs, scopeStatic)
	if len(st) != 3 {
		t.Fatalf("static = %+v", st)
	}
	all := filterRecords(recs, scopeAll)
	if len(all) != 5 {
		t.Fatalf("all = %+v", all)
	}
}
