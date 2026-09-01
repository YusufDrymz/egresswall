package capture

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// The socket itself is exercised by the learn-e2e CI job; here we only pin
// down the two ways Open refuses, since those are what users hit first.
func TestOpenRefusals(t *testing.T) {
	src, err := Open()
	if err == nil {
		src.Close()
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			t.Fatal("Open should only succeed as root on linux")
		}
		return
	}
	switch {
	case runtime.GOOS != "linux":
		if !strings.Contains(err.Error(), "only linux") {
			t.Fatalf("got %v", err)
		}
	case os.Geteuid() != 0:
		if !strings.Contains(err.Error(), "needs root") {
			t.Fatalf("unprivileged open should say it needs root, got %v", err)
		}
	default:
		t.Fatalf("root on linux should be able to open: %v", err)
	}
}
