// Package policy is the offline half of egresswall: the file format that says
// where a host may talk to, and the matcher that answers "may it talk to this".
// Nothing here touches the network or the kernel, so it runs and tests anywhere.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Verdict int

const (
	Deny Verdict = iota
	Allow
)

func (v Verdict) String() string {
	if v == Allow {
		return "allow"
	}
	return "deny"
}

// Policy is the on-disk shape. Deny rules win over allow rules, and whatever
// matches nothing falls through to Default.
type Policy struct {
	Version int    `yaml:"version"`
	Default string `yaml:"default"`
	Allow   []Rule `yaml:"allow"`
	Deny    []Rule `yaml:"deny,omitempty"`
}

// Rule matches a destination. A rule with neither domains nor cidrs matches
// any host, which is how you say "port 443 anywhere". Ports and proto empty
// mean any.
type Rule struct {
	Name    string   `yaml:"name,omitempty"`
	Domains []string `yaml:"domains,omitempty"`
	CIDRs   []string `yaml:"cidrs,omitempty"`
	Ports   []string `yaml:"ports,omitempty"`
	Proto   string   `yaml:"proto,omitempty"`
	Comment string   `yaml:"comment,omitempty"`
}

// Dest is one outbound connection attempt as the matcher sees it. Domain is
// what DNS said this IP was, if anything did; it may be empty for IP-literal
// connections, and that is a case the policy author has to think about.
type Dest struct {
	Domain string
	IP     netip.Addr
	Port   uint16
	Proto  string
}

type Decision struct {
	Verdict Verdict
	Rule    string // name of the rule that decided, "" when Default did
	Reason  string
}

type portRange struct{ lo, hi uint16 }

type compiledRule struct {
	name     string
	verdict  Verdict
	exact    map[string]struct{} // "example.com"
	suffixes []string            // ".example.com" from "*.example.com"
	prefixes []netip.Prefix
	ports    []portRange
	proto    string
	anyHost  bool
}

// Set is a compiled policy, safe for concurrent Evaluate calls.
type Set struct {
	rules []compiledRule // deny first, then allow, in file order
	def   Verdict
}

func Load(path string) (*Set, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func Parse(raw []byte) (*Set, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Compile(&p)
}

func Compile(p *Policy) (*Set, error) {
	if p.Version != 1 {
		return nil, fmt.Errorf("policy: unsupported version %d (want 1)", p.Version)
	}
	s := &Set{}
	switch p.Default {
	case "deny":
		s.def = Deny
	case "allow":
		s.def = Allow
	default:
		return nil, fmt.Errorf(`policy: default must be "deny" or "allow", got %q`, p.Default)
	}
	var errs []error
	for i, r := range p.Deny {
		c, err := compileRule(r, Deny, fmt.Sprintf("deny[%d]", i))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.rules = append(s.rules, c)
	}
	for i, r := range p.Allow {
		c, err := compileRule(r, Allow, fmt.Sprintf("allow[%d]", i))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.rules = append(s.rules, c)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return s, nil
}

func compileRule(r Rule, v Verdict, pos string) (compiledRule, error) {
	c := compiledRule{name: r.Name, verdict: v, exact: map[string]struct{}{}}
	if c.name == "" {
		c.name = pos
	}
	for _, d := range r.Domains {
		d = NormalizeDomain(d)
		switch {
		case d == "" || d == "*":
			return c, fmt.Errorf("%s: domain %q is not a domain; drop domains: to match any host", pos, d)
		case strings.HasPrefix(d, "*."):
			if strings.Contains(d[2:], "*") {
				return c, fmt.Errorf("%s: only a leading *. wildcard is supported, got %q", pos, d)
			}
			c.suffixes = append(c.suffixes, d[1:]) // keep the dot: ".example.com"
		case strings.Contains(d, "*"):
			return c, fmt.Errorf("%s: only a leading *. wildcard is supported, got %q", pos, d)
		default:
			c.exact[d] = struct{}{}
		}
	}
	for _, cidr := range r.CIDRs {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			// let "10.0.0.5" mean "10.0.0.5/32", people write that
			addr, aerr := netip.ParseAddr(cidr)
			if aerr != nil {
				return c, fmt.Errorf("%s: bad cidr %q", pos, cidr)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		c.prefixes = append(c.prefixes, pfx.Masked())
	}
	for _, p := range r.Ports {
		pr, err := parsePortRange(p)
		if err != nil {
			return c, fmt.Errorf("%s: %w", pos, err)
		}
		c.ports = append(c.ports, pr)
	}
	switch strings.ToLower(r.Proto) {
	case "", "tcp", "udp":
		c.proto = strings.ToLower(r.Proto)
	default:
		return c, fmt.Errorf("%s: proto must be tcp or udp, got %q", pos, r.Proto)
	}
	c.anyHost = len(c.exact) == 0 && len(c.suffixes) == 0 && len(c.prefixes) == 0
	return c, nil
}

func parsePortRange(s string) (portRange, error) {
	lo, hi, found := strings.Cut(strings.TrimSpace(s), "-")
	a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil || a == 0 {
		return portRange{}, fmt.Errorf("bad port %q", s)
	}
	if !found {
		return portRange{uint16(a), uint16(a)}, nil
	}
	b, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil || b == 0 || b < a {
		return portRange{}, fmt.Errorf("bad port range %q", s)
	}
	return portRange{uint16(a), uint16(b)}, nil
}

// NormalizeDomain lowercases and strips the trailing dot DNS answers carry.
func NormalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func (s *Set) Default() Verdict { return s.def }

// Evaluate returns the first matching rule's verdict. Deny rules are checked
// before allow rules regardless of where they sit in the file.
func (s *Set) Evaluate(d Dest) Decision {
	domain := NormalizeDomain(d.Domain)
	proto := strings.ToLower(d.Proto)
	for i := range s.rules {
		r := &s.rules[i]
		if ok, why := r.match(domain, d.IP, d.Port, proto); ok {
			return Decision{Verdict: r.verdict, Rule: r.name, Reason: why}
		}
	}
	return Decision{Verdict: s.def, Reason: "no rule matched, default " + s.def.String()}
}

func (r *compiledRule) match(domain string, ip netip.Addr, port uint16, proto string) (bool, string) {
	if r.proto != "" && proto != "" && r.proto != proto {
		return false, ""
	}
	if len(r.ports) > 0 {
		hit := false
		for _, pr := range r.ports {
			if port >= pr.lo && port <= pr.hi {
				hit = true
				break
			}
		}
		if !hit {
			return false, ""
		}
	}
	if r.anyHost {
		return true, "any host"
	}
	if domain != "" {
		if _, ok := r.exact[domain]; ok {
			return true, "domain " + domain
		}
		for _, suf := range r.suffixes {
			if strings.HasSuffix(domain, suf) {
				return true, "domain " + domain + " matches *" + suf
			}
		}
	}
	if ip.IsValid() {
		ip = ip.Unmap()
		for _, pfx := range r.prefixes {
			if pfx.Contains(ip) {
				return true, "ip " + ip.String() + " in " + pfx.String()
			}
		}
	}
	return false, ""
}
