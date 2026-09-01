package policy

import (
	"net/netip"
	"strings"
	"testing"
)

const sample = `
version: 1
default: deny
deny:
  - name: no-metadata
    cidrs: ["169.254.169.254"]
allow:
  - name: package-registries
    domains: ["registry.npmjs.org", "*.pypi.org"]
    ports: ["443"]
  - name: github
    domains: ["github.com", "*.github.com"]
    ports: ["443", "22"]
  - name: internal
    cidrs: ["10.0.0.0/8"]
  - name: dns
    ports: ["53"]
    proto: udp
`

func mustParse(t *testing.T, raw string) *Set {
	t.Helper()
	s, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestEvaluate(t *testing.T) {
	s := mustParse(t, sample)
	cases := []struct {
		name string
		d    Dest
		want Verdict
		rule string
	}{
		{"exact domain", Dest{Domain: "registry.npmjs.org", Port: 443, Proto: "tcp"}, Allow, "package-registries"},
		{"trailing dot and case from dns", Dest{Domain: "Registry.NPMJS.org.", Port: 443}, Allow, "package-registries"},
		{"wildcard subdomain", Dest{Domain: "files.pypi.org", Port: 443}, Allow, "package-registries"},
		{"wildcard does not cover apex", Dest{Domain: "pypi.org", Port: 443}, Deny, ""},
		{"wildcard is not a substring match", Dest{Domain: "evilpypi.org", Port: 443}, Deny, ""},
		{"wrong port", Dest{Domain: "registry.npmjs.org", Port: 80}, Deny, ""},
		{"second port in list", Dest{Domain: "github.com", Port: 22}, Allow, "github"},
		{"cidr", Dest{IP: addr("10.20.30.40"), Port: 5432}, Allow, "internal"},
		{"cidr miss", Dest{IP: addr("11.0.0.1"), Port: 5432}, Deny, ""},
		{"ipv4-mapped ipv6 hits ipv4 cidr", Dest{IP: addr("::ffff:10.1.1.1"), Port: 80}, Allow, "internal"},
		{"deny beats allow", Dest{IP: addr("169.254.169.254"), Domain: "github.com", Port: 443}, Deny, "no-metadata"},
		{"any-host rule with proto", Dest{IP: addr("1.1.1.1"), Port: 53, Proto: "udp"}, Allow, "dns"},
		{"any-host rule, wrong proto", Dest{IP: addr("1.1.1.1"), Port: 53, Proto: "tcp"}, Deny, ""},
		{"unknown proto on dest matches proto rule", Dest{IP: addr("1.1.1.1"), Port: 53}, Allow, "dns"},
		{"ip literal with no dns name", Dest{IP: addr("104.16.0.1"), Port: 443}, Deny, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.Evaluate(tc.d)
			if got.Verdict != tc.want || got.Rule != tc.rule {
				t.Fatalf("got %s by %q (%s), want %s by %q", got.Verdict, got.Rule, got.Reason, tc.want, tc.rule)
			}
			if got.Reason == "" {
				t.Fatal("every decision needs a reason")
			}
		})
	}
}

func TestDefaultAllow(t *testing.T) {
	s := mustParse(t, "version: 1\ndefault: allow\n")
	if got := s.Evaluate(Dest{IP: addr("8.8.8.8"), Port: 443}); got.Verdict != Allow {
		t.Fatalf("got %v", got)
	}
}

func TestRuleOrderWithinVerdict(t *testing.T) {
	s := mustParse(t, `
version: 1
default: deny
allow:
  - name: first
    domains: ["a.example.com"]
  - name: second
    domains: ["*.example.com"]
`)
	if got := s.Evaluate(Dest{Domain: "a.example.com", Port: 1}); got.Rule != "first" {
		t.Fatalf("want first rule in file order, got %q", got.Rule)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"version", "version: 2\ndefault: deny\n", "unsupported version"},
		{"default", "version: 1\ndefault: maybe\n", "default must be"},
		{"unknown field", "version: 1\ndefault: deny\nallwo: []\n", "field allwo not found"},
		{"mid wildcard", "version: 1\ndefault: deny\nallow:\n  - domains: ['a.*.com']\n", "leading *. wildcard"},
		{"bare star", "version: 1\ndefault: deny\nallow:\n  - domains: ['*']\n", "not a domain"},
		{"bad cidr", "version: 1\ndefault: deny\nallow:\n  - cidrs: ['10.0.0.0/33']\n", "bad cidr"},
		{"bad port", "version: 1\ndefault: deny\nallow:\n  - ports: ['0']\n", "bad port"},
		{"inverted range", "version: 1\ndefault: deny\nallow:\n  - ports: ['9000-8000']\n", "bad port range"},
		{"proto", "version: 1\ndefault: deny\nallow:\n  - proto: icmp\n", "proto must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAllErrorsReported(t *testing.T) {
	_, err := Parse([]byte("version: 1\ndefault: deny\nallow:\n  - cidrs: ['x']\n  - ports: ['0']\n"))
	if err == nil || !strings.Contains(err.Error(), "allow[0]") || !strings.Contains(err.Error(), "allow[1]") {
		t.Fatalf("want both rules named in the error, got %v", err)
	}
}

func TestSingleAddressAsCIDR(t *testing.T) {
	s := mustParse(t, "version: 1\ndefault: deny\nallow:\n  - cidrs: ['192.0.2.7']\n")
	if got := s.Evaluate(Dest{IP: addr("192.0.2.7"), Port: 80}); got.Verdict != Allow {
		t.Fatalf("got %v", got)
	}
	if got := s.Evaluate(Dest{IP: addr("192.0.2.8"), Port: 80}); got.Verdict != Deny {
		t.Fatalf("got %v", got)
	}
}
