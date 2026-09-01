//go:build !linux

package capture

import "errors"

type Source struct{}

func Open() (*Source, error) {
	return nil, errors.New("capture: only linux is supported (AF_PACKET)")
}

func (s *Source) Read() ([]byte, bool, error) { return nil, false, errors.ErrUnsupported }
func (s *Source) Close() error                { return nil }
