// Package procs answers "which process opened this socket" from /proc: the
// local address of a connection leads to a socket inode, the inode to a pid,
// the pid to its cgroup. That is what lets learn say which service talked
// where, and enforce evaluate cgroup rules in user space.
package procs

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// Owner is what we know about the process behind a socket.
type Owner struct {
	PID    int
	Comm   string
	Cgroup string // cgroup v2 path relative to the root, "" if unknown
}

// netEntry is one row of /proc/net/{tcp,tcp6,udp,udp6}.
type netEntry struct {
	local netip.Addr
	port  uint16
	inode uint64
}

// parseNetLine reads a row like
//
//	0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0  0 12345 1 ...
//
// Addresses are hex in host byte order per 32-bit word, which on the
// machines this runs on means little endian.
func parseNetLine(line string) (netEntry, bool) {
	f := strings.Fields(line)
	if len(f) < 10 || !strings.HasSuffix(f[0], ":") {
		return netEntry{}, false
	}
	addr, portHex, ok := strings.Cut(f[1], ":")
	if !ok {
		return netEntry{}, false
	}
	raw, err := hex.DecodeString(addr)
	if err != nil {
		return netEntry{}, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netEntry{}, false
	}
	inode, err := strconv.ParseUint(f[9], 10, 64)
	if err != nil {
		return netEntry{}, false
	}
	var ip netip.Addr
	switch len(raw) {
	case 4:
		ip = netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
	case 16:
		var b [16]byte
		for w := 0; w < 4; w++ {
			b[w*4], b[w*4+1], b[w*4+2], b[w*4+3] = raw[w*4+3], raw[w*4+2], raw[w*4+1], raw[w*4]
		}
		ip = netip.AddrFrom16(b).Unmap()
	default:
		return netEntry{}, false
	}
	return netEntry{local: ip, port: uint16(port), inode: inode}, true
}

// cgroupFromProc turns the contents of /proc/<pid>/cgroup into a relative
// v2 path. On a v1-only host there is no "0::" line and the answer is "".
func cgroupFromProc(contents string) string {
	for _, line := range strings.Split(contents, "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.Trim(rest, "/")
		}
	}
	return ""
}
