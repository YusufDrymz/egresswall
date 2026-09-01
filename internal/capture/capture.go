// Package capture reads raw frames off every interface with the kernel's
// verdict on direction attached. Linux only; everything above it is portable.
package capture

import "errors"

var ErrTimeout = errors.New("capture: read timeout")
