package kmsg

import "net/netip"

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
