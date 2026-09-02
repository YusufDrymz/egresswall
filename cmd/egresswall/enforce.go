package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/YusufDrymz/egresswall/internal/capture"
	"github.com/YusufDrymz/egresswall/internal/dnswatch"
	"github.com/YusufDrymz/egresswall/internal/kmsg"
	"github.com/YusufDrymz/egresswall/internal/learn"
	"github.com/YusufDrymz/egresswall/internal/nft"
	"github.com/YusufDrymz/egresswall/internal/packet"
	"github.com/YusufDrymz/egresswall/internal/policy"
)

func runEnforce(args []string) error {
	fs := flag.NewFlagSet("enforce", flag.ExitOnError)
	path := fs.String("policy", "egresswall.yaml", "policy file")
	dryRun := fs.Bool("dry-run", false, "do not touch nftables; watch traffic and say what the policy would have done")
	print := fs.Bool("print", false, "print the nftables ruleset the policy turns into and exit")
	off := fs.Bool("off", false, "remove a leftover egresswall table and exit")
	verbose := fs.Bool("verbose", false, "also report allowed connections")
	forward := fs.Bool("forward", false, "also filter traffic this host forwards: containers, and anything routed through it")
	fs.Parse(args)

	if *off {
		removed, err := nft.Remove()
		if err != nil {
			return err
		}
		if removed {
			fmt.Println("egresswall table removed")
		} else {
			fmt.Println("no egresswall table was loaded")
		}
		return nil
	}

	set, err := policy.Load(*path)
	if err != nil {
		return err
	}
	plan := nft.Build(set)
	plan.Forward = *forward
	if *print {
		fmt.Print(plan.Text())
		return nil
	}

	src, err := capture.Open()
	if err != nil {
		return err
	}
	defer src.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dns := dnswatch.New(learnMinTTL)
	var handle *nft.Handle
	if *dryRun {
		fmt.Fprintf(os.Stderr, "egresswall: dry run, nothing is blocked; reporting what %s would do\n", *path)
	} else {
		handle, err = nft.Apply(plan)
		if err != nil {
			return err
		}
		defer func() {
			if err := handle.Close(); err != nil {
				fmt.Fprintln(os.Stderr, "egresswall: removing table:", err)
			} else {
				fmt.Fprintln(os.Stderr, "egresswall: table removed, host is unfiltered again")
			}
		}()
		fmt.Fprintf(os.Stderr, "egresswall: enforcing %s (%d rules, %d address sets)\n", *path, len(plan.Atoms), len(plan.Sets))
		warnMissing(handle.Missing())
		seed(set, handle, dns)
		go func() {
			err := kmsg.Tail(ctx, func(ev kmsg.Event) {
				name, _ := dns.Lookup(ev.Dst, time.Now())
				rule := "default deny"
				if ev.Rule != "" {
					rule = "rule " + ev.Rule
				}
				fmt.Fprintf(os.Stderr, "refused  %s  %s\n", destText(ev.Dst.String(), name, ev.Port, ev.Proto), rule)
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "egresswall: not reading the kernel log, refusals will only be in dmesg:", err)
			}
		}()
	}

	obs := learn.NewObserver(dns)
	var seen sync.Map // "host:port/proto" -> last report, to keep retries from spamming
	obs.OnNew = func(e learn.Entry) {}
	report := func(p packet.Packet, now time.Time) {
		d := policy.Dest{IP: p.Dst, Port: p.DstPort}
		if p.IsUDP() {
			d.Proto = "udp"
		} else {
			d.Proto = "tcp"
		}
		if name, ok := dns.Lookup(p.Dst, now); ok {
			d.Domain = name
		}
		d.Cgroup = ownerCgroup(p.Src, p.SrcPort, d.Proto)
		key := fmt.Sprintf("%s:%d/%s", p.Dst, p.DstPort, d.Proto)
		if last, ok := seen.Load(key); ok && now.Sub(last.(time.Time)) < 10*time.Second {
			return
		}
		seen.Store(key, now)
		dec := set.Evaluate(d)
		if dec.Verdict == policy.Allow && !*verbose {
			return
		}
		word := "allow"
		if dec.Verdict == policy.Deny {
			word = "deny "
			if *dryRun {
				word = "would deny"
			}
		}
		from := ""
		if d.Cgroup != "" {
			from = "  from " + d.Cgroup
		}
		fmt.Fprintf(os.Stderr, "%s  %s  %s%s\n", word, destText(p.Dst.String(), d.Domain, p.DstPort, d.Proto), dec.Reason, from)
	}

	lastSweep := time.Now()
	lastCgroupCheck := lastSweep
	for ctx.Err() == nil {
		frame, outgoing, err := src.Read()
		if errors.Is(err, capture.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		now := time.Now()
		p, err := packet.Parse(frame)
		if err != nil {
			continue
		}
		if !outgoing && p.IsUDP() && p.SrcPort == 53 {
			if a, err := dnswatch.Parse(p.Payload); err == nil && a.Name != "" {
				dns.Record(a, now)
				if handle != nil {
					feed(set, handle, a)
				}
			}
			continue
		}
		if outgoing && ((p.IsTCP() && p.SYN && !p.ACK) || p.IsUDP()) && !p.Dst.IsLoopback() {
			report(p, now)
		}
		if now.Sub(lastSweep) > 30*time.Second {
			dns.Purge(now)
			lastSweep = now
		}
		// a service that was not running when we loaded the table has no
		// cgroup yet; once it appears, reload so its rules take effect
		if handle != nil && now.Sub(lastCgroupCheck) > 5*time.Second {
			lastCgroupCheck = now
			if appeared(handle.Missing()) {
				fresh, err := nft.Apply(plan)
				if err != nil {
					fmt.Fprintln(os.Stderr, "egresswall: reloading for new cgroups:", err)
					continue
				}
				handle = fresh
				fmt.Fprintln(os.Stderr, "egresswall: table reloaded, cgroup rules now active")
				warnMissing(handle.Missing())
				seed(set, handle, dns)
			}
		}
	}
	return nil
}

func warnMissing(missing []string) {
	for _, cg := range missing {
		fmt.Fprintf(os.Stderr, "egresswall: cgroup %s does not exist yet, its rules are inactive until it does\n", cg)
	}
}

func appeared(missing []string) bool {
	for _, cg := range missing {
		if nft.CgroupExists(cg) {
			return true
		}
	}
	return false
}

// feed puts a DNS answer's addresses into the sets of every rule whose
// domain patterns cover the name, deny rules included.
func feed(set *policy.Set, h *nft.Handle, a dnswatch.Answer) {
	rules := set.DomainRules(a.Name)
	if len(rules) == 0 {
		return
	}
	for _, ad := range a.Addrs {
		ttl := ad.TTL
		if ttl < learnMinTTL {
			ttl = learnMinTTL
		}
		for _, i := range rules {
			if err := h.AddAddr(nft.SetFor(i, ad.IP), ad.IP, ttl); err != nil {
				fmt.Fprintf(os.Stderr, "egresswall: adding %s for %s: %v\n", ad.IP, a.Name, err)
			}
		}
	}
}

// seed resolves the exact names in the policy once at startup, so processes
// that cached an address before we started are not refused until they
// happen to resolve again. Wildcards cannot be seeded.
func seed(set *policy.Set, h *nft.Handle, dns *dnswatch.Cache) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, r := range set.Rules() {
		for _, name := range r.Exact {
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "egresswall: seed %s: %v\n", name, err)
				continue
			}
			a := dnswatch.Answer{Name: name}
			for _, ip := range ips {
				a.Addrs = append(a.Addrs, dnswatch.Addr{IP: ip.Unmap(), TTL: learnMinTTL})
			}
			dns.Record(a, time.Now())
			feed(set, h, a)
		}
	}
}

func destText(ip, name string, port uint16, proto string) string {
	if name != "" {
		return fmt.Sprintf("%s (%s):%d %s", ip, name, port, proto)
	}
	return fmt.Sprintf("%s:%d %s", ip, port, proto)
}
