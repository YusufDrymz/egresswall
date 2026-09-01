//go:build !linux

package nft

import (
	"errors"
	"net/netip"
	"time"
)

var errLinuxOnly = errors.New("nft: enforce needs linux with nftables")

type Handle struct{}

func Apply(*Plan) (*Handle, error) { return nil, errLinuxOnly }

func (h *Handle) AddAddr(string, netip.Addr, time.Duration) error { return errLinuxOnly }
func (h *Handle) Close() error                                    { return nil }

func Remove() (bool, error) { return false, errLinuxOnly }
