// Package alert ships refusals somewhere a person will see them. The rules
// are the same for every sink: never block the caller, never lose the count
// of what was dropped, and never turn one noisy process into a flood of
// requests.
package alert

import (
	"net/netip"
	"time"
)

// Event is one refused connection.
type Event struct {
	At     time.Time
	Rule   string // "" when the default deny refused it
	Host   string // dns name if one was known for the address
	IP     netip.Addr
	Port   uint16
	Proto  string
	Cgroup string
}

// key is what makes two events "the same thing happening again": the same
// destination refused by the same rule from the same place.
type key struct {
	rule, host, cgroup string
	ip                 netip.Addr
	port               uint16
	proto              string
}

func (e Event) key() key {
	return key{e.Rule, e.Host, e.Cgroup, e.IP, e.Port, e.Proto}
}

// Group is a coalesced event: one destination, however many attempts.
type Group struct {
	Event
	Count int       `json:"count"`
	Last  time.Time `json:"last"`
}

// Sink takes events from the enforcing loop. Send must not block.
type Sink interface {
	Send(Event)
	Close() error
}
