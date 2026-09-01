//go:build !linux

package kmsg

import (
	"context"
	"errors"
)

func Tail(context.Context, func(Event)) error { return errors.New("kmsg: linux only") }
