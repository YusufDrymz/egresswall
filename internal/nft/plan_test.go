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
	// deny metadata (1) + dns (1) + registries v4/v6 (2) + internal v4+v6 (2)
	// + wide: 2 port ranges (2)
	if len(p.Atoms) != 8 {
		t.Fatalf("want 8 atoms, got %d: %+v", len(p.Atoms), p.Atoms)
	}
	first := p.Atoms[0]
	if first.Verdict != policy.Deny || first.Family != V4 || first.Prefix != netip.MustParsePrefix("169.254.169.254/32") || first.Proto != "" {
		t.Fatalf("deny atom first: %+v", first)
	}
	if a := p.Atoms[1]; a.Family != AnyFamily || a.Proto != "udp" || a.Port != (policy.PortRange{Lo: 53, Hi: 53}) {
		t.Fatalf("dns atom: %+v", a)
	}
	if a := p.Atoms[3]; a.Family != V6 || a.Set != "r2_v6" || a.Proto != "" || a.Port.Lo != 443 {
		t.Fatalf("registries v6 atom keeps proto open: %+v", a)
	}
	if a := p.Atoms[5]; a.Family != V6 || a.Prefix != netip.MustParsePrefix("fd00::/8") {
		t.Fatalf("internal v6 atom: %+v", a)
	}
	if a := p.Atoms[6]; a.Proto != "" || a.Port != (policy.PortRange{Lo: 8000, Hi: 8100}) {
		t.Fatalf("wide: %+v", a)
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
		"ip6 daddr fe80::/10 accept",
		"ip6 daddr ff00::/8 accept",
		"ip daddr 224.0.0.0/4 accept",
		`ip daddr 169.254.169.254 log prefix "egresswall deny[no-metadata]: " reject with icmpx type admin-prohibited`,
		"udp dport 53 accept",
		"ip daddr @r2_v4 meta l4proto { tcp, udp } th dport 443 accept",
		"ip6 daddr @r2_v6 meta l4proto { tcp, udp } th dport 443 accept",
		"ip daddr 10.0.0.0/8 accept",
		"ip6 daddr fd00::/8 accept",
		"meta l4proto { tcp, udp } th dport 8000-8100 accept",
		"meta l4proto { tcp, udp } th dport 9000 accept",
		`log prefix "egresswall default-deny: " reject with icmpx type admin-prohibited`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// the deny rule must precede every policy accept, but housekeeping comes first
	if strings.Index(out, "deny[no-metadata]") > strings.Index(out, "udp dport 53 accept") {
		t.Fatal("deny rules must come before allow rules")
	}
	if strings.Index(out, "ff00::/8 accept") > strings.Index(out, "deny[no-metadata]") {
		t.Fatal("link-local housekeeping is not subject to the policy")
	}
}

func TestTextForward(t *testing.T) {
	p := build(t, sample)
	if strings.Contains(p.Text(), "hook forward") {
		t.Fatal("forward chain is opt-in")
	}
	p.Forward = true
	out := p.Text()
	i := strings.Index(out, "chain forward {")
	if i < 0 {
		t.Fatalf("no forward chain:\n%s", out)
	}
	fwd := out[i:]
	for _, want := range []string{
		"type filter hook forward priority filter; policy drop;",
		`oifname "docker*" accept`,
		`oifname "br-*" accept`,
		"ct state established,related accept",
		"ip daddr @r2_v4 meta l4proto { tcp, udp } th dport 443 accept",
		`log prefix "egresswall default-deny: "`,
	} {
		if !strings.Contains(fwd, want) {
			t.Fatalf("forward chain missing %q:\n%s", want, fwd)
		}
	}
	if strings.Contains(fwd, `oif "lo"`) {
		t.Fatal("loopback rule makes no sense on the forward hook")
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

func TestCgroupAtoms(t *testing.T) {
	p := build(t, `
version: 1
default: deny
allow:
  - name: app-db
    cidrs: ["10.0.0.5"]
    ports: ["5432"]
    proto: tcp
    cgroup: system.slice/app.service
  - name: app-api
    domains: ["api.example.com"]
    ports: ["443"]
    cgroup: system.slice/app.service
`)
	if p.Atoms[0].Cgroup != "system.slice/app.service" || p.Atoms[1].Cgroup != p.Atoms[0].Cgroup {
		t.Fatalf("%+v", p.Atoms)
	}
	out := p.Text()
	for _, want := range []string{
		`socket cgroupv2 level 2 "system.slice/app.service" ip daddr 10.0.0.5 tcp dport 5432 accept`,
		`socket cgroupv2 level 2 "system.slice/app.service" ip daddr @r1_v4 meta l4proto { tcp, udp } th dport 443 accept`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if CgroupLevel("a") != 1 || CgroupLevel("a/b/c") != 3 {
		t.Fatal("level")
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
