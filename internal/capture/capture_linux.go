//go:build linux

package capture

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Source is an AF_PACKET socket in cooked (SOCK_DGRAM) mode bound to every
// interface: frames arrive without the link-layer header, so Read hands back
// bytes that start at the IP header. Needs CAP_NET_RAW, in practice root.
type Source struct {
	fd  int
	buf []byte
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func Open() (*Source, error) {
	proto := int(htons(syscall.ETH_P_ALL))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("capture: opening a raw socket needs root (CAP_NET_RAW): %w", err)
		}
		return nil, fmt.Errorf("capture: socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL)}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: bind: %w", err)
	}
	// wake up every second so the caller can notice it was asked to stop
	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: rcvtimeo: %w", err)
	}
	return &Source{fd: fd, buf: make([]byte, 65536)}, nil
}

// Read blocks for at most a second. On timeout it returns ErrTimeout and no
// frame. The returned slice is reused by the next call.
func (s *Source) Read() (frame []byte, outgoing bool, err error) {
	for {
		n, from, err := syscall.Recvfrom(s.fd, s.buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, false, ErrTimeout
			}
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return nil, false, os.NewSyscallError("recvfrom", err)
		}
		ll, ok := from.(*syscall.SockaddrLinklayer)
		if !ok {
			continue
		}
		return s.buf[:n], ll.Pkttype == syscall.PACKET_OUTGOING, nil
	}
}

func (s *Source) Close() error { return syscall.Close(s.fd) }
