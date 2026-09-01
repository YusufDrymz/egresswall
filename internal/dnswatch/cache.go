// Package dnswatch turns DNS answers seen on the wire into an IP -> name map.
// It only ever looks at responses, it never sends a query itself.
package dnswatch

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/YusufDrymz/egresswall/internal/policy"
)

var ErrNotResponse = errors.New("dnswatch: not a response")

type entry struct {
	name string
	exp  time.Time
}

// Cache maps resolved addresses back to the name that was asked for. When an
// address answers for several names the most recent answer wins; that is the
// name the process is most likely about to connect to.
type Cache struct {
	// MinTTL stretches short TTLs. Applications cache resolutions well past
	// the TTL, and a connection that shows up after the wire TTL expired
	// would otherwise be attributed to nobody.
	MinTTL time.Duration

	mu   sync.Mutex
	byIP map[netip.Addr]entry
}

func New(minTTL time.Duration) *Cache {
	return &Cache{MinTTL: minTTL, byIP: map[netip.Addr]entry{}}
}

// Observe parses one DNS message. Non-responses and messages without A/AAAA
// answers are not errors, they just record nothing. Answers are recorded
// under the question name, not the CNAME they came through: the policy author
// thinks in terms of what the app asked for.
func (c *Cache) Observe(msg []byte, now time.Time) (int, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return 0, err
	}
	if !h.Response {
		return 0, ErrNotResponse
	}
	q, err := p.Question()
	if err != nil {
		return 0, err
	}
	name := policy.NormalizeDomain(q.Name.String())
	if name == "" {
		return 0, nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return 0, err
	}
	n := 0
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return n, err
		}
		ttl := time.Duration(rh.TTL) * time.Second
		if ttl < c.MinTTL {
			ttl = c.MinTTL
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return n, err
			}
			c.put(netip.AddrFrom4(r.A), name, now.Add(ttl))
			n++
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return n, err
			}
			c.put(netip.AddrFrom16(r.AAAA), name, now.Add(ttl))
			n++
		default:
			if err := p.SkipAnswer(); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

func (c *Cache) put(ip netip.Addr, name string, exp time.Time) {
	c.mu.Lock()
	c.byIP[ip] = entry{name: name, exp: exp}
	c.mu.Unlock()
}

// Lookup returns the name an address last resolved from, if it has not expired.
func (c *Cache) Lookup(ip netip.Addr, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byIP[ip.Unmap()]
	if !ok || now.After(e.exp) {
		return "", false
	}
	return e.name, true
}

// Purge drops expired entries; call it now and then from a long-running loop.
func (c *Cache) Purge(now time.Time) {
	c.mu.Lock()
	for ip, e := range c.byIP {
		if now.After(e.exp) {
			delete(c.byIP, ip)
		}
	}
	c.mu.Unlock()
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byIP)
}
