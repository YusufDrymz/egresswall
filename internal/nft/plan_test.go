package nft

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/YusufDrymz/egresswall/internal/policy"
)

const sample = `
version: 1
default: deny
deny:
  - name: no-metadata
    cidrs: ["169.254.169.254"]
allow:
  - name: dns
    ports: ["53"]
    proto: udp
  - name: registries
    domains: ["registry.npmjs.org", "*.pypi.org"]
    ports: ["443"]
  - name: internal
    cidrs: ["10.0.0.0/8", "fd00::/8"]
  - name: wide
    ports: ["8000-8100", "9000"]
`

func build(t *testing.T, raw string) *Plan {
	t.Helper()
	s, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return Build(s)
}

func TestBuildExpansion(t *testing.T) {
	p := build(t, sample)
	if !p.DefaultDeny {
		t.Fatal("default deny lost")
	}
	if len(p.Sets) != 2 || p.Sets[0].Name != "r2_v4" || p.Sets[1].Name != "r2_v6" || p.Sets[0].Rule != 2 {
		t.Fatalf("sets: %+v", p.Sets)
	}
	// deny metadata (1) + dns (1) + registries: port without proto is tcp and
	// udp, times v4/v6 (4) + internal v4+v6 (2) + wide: 2 ranges x tcp/udp (4)
	if len(p.Atoms) != 12 {
		t.Fatalf("want 12 atoms, got %d: %+v", len(p.Atoms), p.Atoms)
	}
	first := p.Atoms[0]
	if first.Verdict != policy.Deny || first.Family != V4 || first.Prefix != netip.MustParsePrefix("169.254.169.254/32") || first.Proto != "" {
		t.Fatalf("deny atom first: %+v", first)
	}
	if a := p.Atoms[1]; a.Family != AnyFamily || a.Proto != "udp" || a.Port != (policy.PortRange{Lo: 53, Hi: 53}) {
		t.Fatalf("dns atom: %+v", a)
	}
	if a := p.Atoms[4]; a.Family != V6 || a.Set != "r2_v6" || a.Proto != "tcp" {
		t.Fatalf("registries v6 atom: %+v", a)
	}
	if a := p.Atoms[7]; a.Family != V6 || a.Prefix != netip.MustParsePrefix("fd00::/8") {
		t.Fatalf("internal v6 atom: %+v", a)
	}
	protos := map[string]int{}
	for _, a := range p.Atoms[8:] {
		protos[a.Proto]++
	}
	if protos["tcp"] != 2 || protos["udp"] != 2 {
		t.Fatalf("port without proto must expand to tcp and udp: %v", protos)
	}
}

func TestText(t *testing.T) {
	out := build(t, sample).Text()
	for _, want := range []string{
		"table inet egresswall {",
		"set r2_v4 {\n\t\ttype ipv4_addr\n\t\tflags timeout",
		"set r2_v6 {\n\t\ttype ipv6_addr",
		"type filter hook output priority filter; policy drop;",
		`oif "lo" accept`,
		"ct state established,related accept",
		`ip daddr 169.254.169.254 log prefix "egresswall deny[no-metadata]: " reject with icmpx type admin-prohibited`,
		"udp dport 53 accept",
		"ip daddr @r2_v4 tcp dport 443 accept",
		"ip6 daddr @r2_v6 tcp dport 443 accept",
		"ip daddr 10.0.0.0/8 accept",
		"ip6 daddr fd00::/8 accept",
		"tcp dport 8000-8100 accept",
		"udp dport 9000 accept",
		`log prefix "egresswall default-deny: " reject with icmpx type admin-prohibited`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// the deny rule must precede every accept
	if strings.Index(out, "deny[no-metadata]") > strings.Index(out, "udp dport 53 accept") {
		t.Fatal("deny rules must come before allow rules")
	}
}

func TestTextDefaultAllow(t *testing.T) {
	out := build(t, "version: 1\ndefault: allow\nallow:\n  - proto: tcp\n").Text()
	if !strings.Contains(out, "policy accept;") || strings.Contains(out, "default-deny") {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(out, "meta l4proto tcp accept") {
		t.Fatalf("proto without port: %s", out)
	}
}

func TestSetFor(t *testing.T) {
	if SetFor(3, netip.MustParseAddr("::ffff:1.2.3.4")) != "r3_v4" || SetFor(3, netip.MustParseAddr("2001:db8::1")) != "r3_v6" {
		t.Fatal("family detection")
	}
}

func TestLogPrefixCapped(t *testing.T) {
	long := strings.Repeat("x", 200)
	if p := LogPrefix(long); len(p) > 127 || !strings.HasSuffix(p, "..: ") {
		t.Fatalf("%d %q", len(p), p)
	}
}
