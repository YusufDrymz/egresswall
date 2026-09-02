//go:build !linux

package procs

import "net/netip"

func Lookup(netip.Addr, uint16, string) (Owner, bool) { return Owner{}, false }
