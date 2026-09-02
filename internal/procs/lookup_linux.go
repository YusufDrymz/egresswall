//go:build linux

package procs

import (
	"bufio"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Lookup finds the process that owns the socket bound to local:port. It is a
// few file reads and one walk of /proc/*/fd, fine for a new flow now and
// then, not for every packet. Short-lived sockets may be gone already; that
// is reported as not found.
func Lookup(local netip.Addr, port uint16, proto string) (Owner, bool) {
	inode, ok := findInode(local, port, proto)
	if !ok {
		return Owner{}, false
	}
	pid, ok := findPID(inode)
	if !ok {
		return Owner{}, false
	}
	o := Owner{PID: pid}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm"); err == nil {
		o.Comm = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup"); err == nil {
		o.Cgroup = cgroupFromProc(string(b))
	}
	return o, true
}

func findInode(local netip.Addr, port uint16, proto string) (uint64, bool) {
	files := []string{"/proc/net/" + proto, "/proc/net/" + proto + "6"}
	local = local.Unmap()
	var fallback uint64
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			e, ok := parseNetLine(sc.Text())
			if !ok || e.port != port || e.inode == 0 {
				continue
			}
			if e.local == local {
				f.Close()
				return e.inode, true
			}
			// a socket bound to 0.0.0.0/:: on that port is the next best guess
			if e.local.IsUnspecified() && fallback == 0 {
				fallback = e.inode
			}
		}
		f.Close()
	}
	return fallback, fallback != 0
}

func findPID(inode uint64) (int, bool) {
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if target, err := os.Readlink(filepath.Join(fdDir, fd.Name())); err == nil && target == want {
				return pid, true
			}
		}
	}
	return 0, false
}
