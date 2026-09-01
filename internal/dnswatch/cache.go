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

// Addr is one A/AAAA record from an answer.
type Addr struct {
	IP  netip.Addr
	TTL time.Duration
}

// Answer is what a response said: the name that was asked for and the
// addresses it resolved to. Answers are recorded under the question name,
// not the CNAME they came through: the policy author thinks in terms of what
// the app asked for.
type Answer struct {
	Name  string
	Addrs []Addr
}

// Parse pulls the question name and A/AAAA records out of one DNS message.
// Non-responses are ErrNotResponse; a response without addresses is fine.
func Parse(msg []byte) (Answer, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return Answer{}, err
	}
	if !h.Response {
		return Answer{}, ErrNotResponse
	}
	q, err := p.Question()
	if err != nil {
		return Answer{}, err
	}
	a := Answer{Name: policy.NormalizeDomain(q.Name.String())}
	if err := p.SkipAllQuestions(); err != nil {
		return a, err
	}
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return a, nil
		}
		if err != nil {
			return a, err
		}
		ttl := time.Duration(rh.TTL) * time.Second
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return a, err
			}
			a.Addrs = append(a.Addrs, Addr{netip.AddrFrom4(r.A), ttl})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return a, err
			}
			a.Addrs = append(a.Addrs, Addr{netip.AddrFrom16(r.AAAA), ttl})
		default:
			if err := p.SkipAnswer(); err != nil {
				return a, err
			}
		}
	}
}

// Observe parses one DNS message and records its addresses. It returns how
// many it recorded.
func (c *Cache) Observe(msg []byte, now time.Time) (int, error) {
	a, err := Parse(msg)
	if err != nil {
		return 0, err
	}
	if a.Name == "" {
		return 0, nil
	}
	c.Record(a, now)
	return len(a.Addrs), nil
}

// Record stores an already parsed answer, stretching TTLs to MinTTL.
func (c *Cache) Record(a Answer, now time.Time) {
	for _, ad := range a.Addrs {
		ttl := ad.TTL
		if ttl < c.MinTTL {
			ttl = c.MinTTL
		}
		c.put(ad.IP, a.Name, now.Add(ttl))
	}
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
