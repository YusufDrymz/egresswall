// Package learn watches packets and builds up "this host talks to X on port
// Y" until asked to write that down as a policy.
package learn

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/YusufDrymz/egresswall/internal/dnswatch"
	"github.com/YusufDrymz/egresswall/internal/packet"
)

// Entry is one destination this host was seen connecting to. Host is the DNS
// name when one was seen resolving to the address shortly before, otherwise
// the address itself.
type Entry struct {
	Host   string
	Domain bool // Host is a name, not an address
	Port   uint16
	Proto  string
	First  time.Time
	Last   time.Time
	Hits   int
	IPs    []netip.Addr // addresses seen for a domain entry, for the comment
	// Origins says which cgroups the flows came from, when Owner could tell.
	// The empty cgroup collects flows nobody could be found for.
	Origins map[string]int
}

type key struct {
	host  string
	port  uint16
	proto string
}

type udpTuple struct {
	peer     netip.Addr
	peerPort uint16
	local    uint16
}

// Observer takes every packet the capture hands over and keeps only new
// outbound flows. It is safe for one goroutine feeding packets and another
// calling Entries.
type Observer struct {
	DNS *dnswatch.Cache
	// OnNew fires for each never-seen-before destination, from the feeding
	// goroutine. Keep it quick.
	OnNew func(Entry)
	// Owner, when set, is asked for the cgroup behind a new flow's local
	// address. It runs on the feeding goroutine too.
	Owner func(local netip.Addr, port uint16, proto string) string

	mu      sync.Mutex
	entries map[key]*Entry
	ips     map[key]map[netip.Addr]struct{}
	origins map[key]map[string]int
	// UDP has no SYN, so whoever sent the first packet of a (peer, peer
	// port, our port) tuple is the initiator. Remember both directions for a
	// minute: an outbound packet mirroring something we received is our
	// reply, not a new flow, and an inbound packet mirroring something we
	// sent is a response that must not poison the reply table.
	udpIn  map[udpTuple]time.Time
	udpOut map[udpTuple]time.Time
}

const replyWindow = time.Minute

func NewObserver(dns *dnswatch.Cache) *Observer {
	return &Observer{
		DNS:     dns,
		entries: map[key]*Entry{},
		ips:     map[key]map[netip.Addr]struct{}{},
		origins: map[key]map[string]int{},
		udpIn:   map[udpTuple]time.Time{},
		udpOut:  map[udpTuple]time.Time{},
	}
}

// Packet classifies one frame. outgoing is what the kernel said about the
// direction (PACKET_OUTGOING), which beats guessing from addresses.
func (o *Observer) Packet(p packet.Packet, outgoing bool, now time.Time) {
	if !outgoing {
		if p.IsUDP() {
			if p.SrcPort == 53 {
				o.DNS.Observe(p.Payload, now) // best effort, garbage is fine
			}
			t := udpTuple{p.Src, p.SrcPort, p.DstPort}
			o.mu.Lock()
			if at, sent := o.udpOut[t]; !sent || now.Sub(at) > replyWindow {
				o.udpIn[t] = now
			}
			o.mu.Unlock()
		}
		return
	}
	if !p.Dst.IsValid() || p.Dst.IsLoopback() || p.Dst.IsMulticast() || p.Dst.IsUnspecified() {
		return
	}
	proto := ""
	switch {
	case p.IsTCP():
		if !p.SYN || p.ACK {
			return // only the first packet of a connection we opened
		}
		proto = "tcp"
	case p.IsUDP():
		t := udpTuple{p.Dst, p.DstPort, p.SrcPort}
		o.mu.Lock()
		at, replied := o.udpIn[t]
		if !replied || now.Sub(at) > replyWindow {
			o.udpOut[t] = now
		}
		o.mu.Unlock()
		if replied && now.Sub(at) < replyWindow {
			return
		}
		proto = "udp"
	default:
		return
	}
	origin := ""
	if o.Owner != nil {
		origin = o.Owner(p.Src, p.SrcPort, proto)
	}
	o.record(p.Dst.Unmap(), p.DstPort, proto, origin, now)
}

func (o *Observer) record(ip netip.Addr, port uint16, proto, origin string, now time.Time) {
	host, domain := ip.String(), false
	if name, ok := o.DNS.Lookup(ip, now); ok {
		host, domain = name, true
	}
	k := key{host, port, proto}
	o.mu.Lock()
	e, seen := o.entries[k]
	if !seen {
		e = &Entry{Host: host, Domain: domain, Port: port, Proto: proto, First: now}
		o.entries[k] = e
		o.ips[k] = map[netip.Addr]struct{}{}
		o.origins[k] = map[string]int{}
	}
	e.Hits++
	e.Last = now
	o.ips[k][ip] = struct{}{}
	o.origins[k][origin]++
	snapshot := *e
	o.mu.Unlock()
	if !seen && o.OnNew != nil {
		o.OnNew(snapshot)
	}
}

// Entries returns a sorted copy: domains first, then addresses, then port.
func (o *Observer) Entries() []Entry {
	o.mu.Lock()
	out := make([]Entry, 0, len(o.entries))
	for k, e := range o.entries {
		c := *e
		for ip := range o.ips[k] {
			c.IPs = append(c.IPs, ip)
		}
		sort.Slice(c.IPs, func(i, j int) bool { return c.IPs[i].Less(c.IPs[j]) })
		c.Origins = map[string]int{}
		for cg, n := range o.origins[k] {
			c.Origins[cg] = n
		}
		out = append(out, c)
	}
	o.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Domain != b.Domain {
			return a.Domain
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})
	return out
}

// Sweep forgets reply-suppression state older than the window.
func (o *Observer) Sweep(now time.Time) {
	o.mu.Lock()
	for _, m := range []map[udpTuple]time.Time{o.udpIn, o.udpOut} {
		for t, at := range m {
			if now.Sub(at) > replyWindow {
				delete(m, t)
			}
		}
	}
	o.mu.Unlock()
}
