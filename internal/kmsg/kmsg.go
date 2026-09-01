// Package kmsg reads the refusals egresswall's nftables rules write to the
// kernel log, so the daemon can report them with names attached.
package kmsg

import (
	"net/netip"
	"strconv"
	"strings"
)

// Event is one refused packet as the kernel logged it.
type Event struct {
	Rule  string // "" for the default-deny rule
	Dst   netip.Addr
	Port  uint16
	Proto string
}

// ParseLine understands one /dev/kmsg record:
//
//	6,1234,5678901,-;egresswall deny[x]: IN= OUT=eth0 SRC=10.0.0.2 DST=1.2.3.4 ... PROTO=TCP SPT=5 DPT=443 ...
//
// Anything that is not one of ours returns false.
func ParseLine(line string) (Event, bool) {
	_, msg, ok := strings.Cut(line, ";")
	if !ok {
		msg = line
	}
	var ev Event
	switch {
	case strings.HasPrefix(msg, "egresswall deny["):
		rest := msg[len("egresswall deny["):]
		name, tail, ok := strings.Cut(rest, "]: ")
		if !ok {
			return ev, false
		}
		ev.Rule, msg = name, tail
	case strings.HasPrefix(msg, "egresswall default-deny: "):
		msg = msg[len("egresswall default-deny: "):]
	default:
		return ev, false
	}
	for _, f := range strings.Fields(msg) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "DST":
			if a, err := netip.ParseAddr(v); err == nil {
				ev.Dst = a
			}
		case "DPT":
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				ev.Port = uint16(n)
			}
		case "PROTO":
			ev.Proto = strings.ToLower(v)
		}
	}
	return ev, ev.Dst.IsValid()
}
