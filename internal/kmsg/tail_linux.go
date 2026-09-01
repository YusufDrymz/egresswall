//go:build linux

package kmsg

import (
	"context"
	"fmt"
	"io"
	"os"
)

// Tail reads /dev/kmsg from now on and calls fn for every refusal. It returns
// when the context ends or the device cannot be read; opening it at all
// needs root, and containers usually do not expose it.
func Tail(ctx context.Context, fn func(Event)) error {
	f, err := os.Open("/dev/kmsg")
	if err != nil {
		return fmt.Errorf("kmsg: %w", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return fmt.Errorf("kmsg: seek: %w", err)
	}
	go func() {
		<-ctx.Done()
		f.Close() // unblocks the read below
	}()
	buf := make([]byte, 8192)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// EPIPE means we fell behind and the ring overwrote records; carry on
			if pe, ok := err.(*os.PathError); ok && pe.Err.Error() == "broken pipe" {
				continue
			}
			return fmt.Errorf("kmsg: read: %w", err)
		}
		if ev, ok := ParseLine(string(buf[:n])); ok {
			fn(ev)
		}
	}
}
