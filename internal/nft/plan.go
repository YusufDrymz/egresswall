// Package nft turns a policy into an nftables ruleset. Build and Text are
// portable and tested; Apply talks to the kernel and only exists on Linux.
package nft

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/YusufDrymz/egresswall/internal/policy"
)

const (
	TableName = "egresswall"
	ChainName = "output"
	// kernel log prefixes are capped at 127 bytes
	maxPrefix = 120
)

type Family uint8

const (
	AnyFamily Family = iota
	V4
	V6
)

// Atom is one nftables rule. A policy rule expands into several: one per
// address family it touches, per protocol, per port range. Ranges of ports
// stay ranges; addresses are either a prefix or a set lookup.
type Atom struct {
	Family  Family
	Proto   string // "", "tcp", "udp"
	Port    policy.PortRange
	Prefix  netip.Prefix // valid when the atom matches a cidr
	Set     string       // non-empty when the atom matches a set
	Verdict policy.Verdict
	Rule    string
}

// SetDef is a timeout set holding the addresses a domain rule currently
// resolves to. Two per domain rule, one per family.
type SetDef struct {
	Name   string
	Family Family
	Rule   int // index into policy.Set.Rules()
}

type Plan struct {
	Sets        []SetDef
	Atoms       []Atom
	DefaultDeny bool
}

func setName(rule int, f Family) string {
	if f == V6 {
		return fmt.Sprintf("r%d_v6", rule)
	}
	return fmt.Sprintf("r%d_v4", rule)
}

// SetFor names the set a resolved address for rule i belongs in.
func SetFor(rule int, ip netip.Addr) string {
	if ip.Unmap().Is4() {
		return setName(rule, V4)
	}
	return setName(rule, V6)
}

func Build(s *policy.Set) *Plan {
	p := &Plan{DefaultDeny: s.Default() == policy.Deny}
	for i, r := range s.Rules() {
		hasDomains := len(r.Exact) > 0 || len(r.Suffixes) > 0
		if hasDomains {
			p.Sets = append(p.Sets, SetDef{setName(i, V4), V4, i}, SetDef{setName(i, V6), V6, i})
		}
		protos := []string{r.Proto}
		if r.Proto == "" && len(r.Ports) > 0 {
			// a port without a protocol means both; nft needs them spelled out
			protos = []string{"tcp", "udp"}
		}
		ports := r.Ports
		if len(ports) == 0 {
			ports = []policy.PortRange{{}}
		}
		emit := func(base Atom) {
			for _, proto := range protos {
				for _, port := range ports {
					a := base
					a.Proto, a.Port, a.Verdict, a.Rule = proto, port, r.Verdict, r.Name
					p.Atoms = append(p.Atoms, a)
				}
			}
		}
		if r.AnyHost {
			emit(Atom{Family: AnyFamily})
			continue
		}
		for _, pfx := range r.Prefixes {
			f := V6
			if pfx.Addr().Is4() {
				f = V4
			}
			emit(Atom{Family: f, Prefix: pfx})
		}
		if hasDomains {
			emit(Atom{Family: V4, Set: setName(i, V4)})
			emit(Atom{Family: V6, Set: setName(i, V6)})
		}
	}
	return p
}

// LogPrefix is what a refused packet carries into the kernel log, and what
// the kmsg reader looks for.
func LogPrefix(rule string) string {
	p := "egresswall default-deny: "
	if rule != "" {
		p = "egresswall deny[" + rule + "]: "
	}
	if len(p) > maxPrefix {
		p = p[:maxPrefix-3] + "..: "
	}
	return p
}

// Text renders the plan in nft syntax. It is what -print shows, so an
// operator can read exactly what will go into the kernel; it is not what
// Apply sends, Apply speaks netlink directly.
func (p *Plan) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	for _, s := range p.Sets {
		typ := "ipv4_addr"
		if s.Family == V6 {
			typ = "ipv6_addr"
		}
		fmt.Fprintf(&b, "\tset %s {\n\t\ttype %s\n\t\tflags timeout\n\t}\n", s.Name, typ)
	}
	policyWord := "accept"
	if p.DefaultDeny {
		policyWord = "drop"
	}
	fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook output priority filter; policy %s;\n", ChainName, policyWord)
	b.WriteString("\t\toif \"lo\" accept\n")
	b.WriteString("\t\tct state established,related accept\n")
	for _, a := range p.Atoms {
		b.WriteString("\t\t")
		b.WriteString(a.text())
		b.WriteByte('\n')
	}
	if p.DefaultDeny {
		fmt.Fprintf(&b, "\t\tlog prefix %q reject with icmpx type admin-prohibited\n", LogPrefix(""))
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func (a Atom) text() string {
	var parts []string
	switch {
	case a.Prefix.IsValid():
		parts = append(parts, familyWord(a.Family)+" daddr "+prefixText(a.Prefix))
	case a.Set != "":
		parts = append(parts, familyWord(a.Family)+" daddr @"+a.Set)
	}
	if a.Proto != "" {
		if a.Port.Hi != 0 {
			parts = append(parts, a.Proto+" dport "+portText(a.Port))
		} else {
			parts = append(parts, "meta l4proto "+a.Proto)
		}
	}
	if a.Verdict == policy.Allow {
		parts = append(parts, "accept")
	} else {
		parts = append(parts, fmt.Sprintf("log prefix %q reject with icmpx type admin-prohibited", LogPrefix(a.Rule)))
	}
	return strings.Join(parts, " ")
}

func familyWord(f Family) string {
	if f == V6 {
		return "ip6"
	}
	return "ip"
}

func prefixText(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

func portText(r policy.PortRange) string {
	if r.Lo == r.Hi {
		return fmt.Sprint(r.Lo)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}
