//go:build !linux

package nft

import "errors"

var errLinuxOnly = errors.New("nft: enforce needs linux with nftables")

type Handle struct{}

func Apply(*Plan) (*Handle, error) { return nil, errLinuxOnly }

func (h *Handle) AddAddrs([]Add) error { return errLinuxOnly }
func (h *Handle) Close() error         { return nil }
func (h *Handle) Missing() []string    { return nil }

func Remove() (bool, error) { return false, errLinuxOnly }

func CgroupExists(string) bool { return false }
