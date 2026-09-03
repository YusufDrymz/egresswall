//go:build linux

package nft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/YusufDrymz/egresswall/internal/policy"
)

// Handle is a plan that has been loaded into the kernel.
type Handle struct {
	conn  *nftables.Conn
	table *nftables.Table
	sets  map[string]*nftables.Set
	anon  int // counter for anonymous set names, nft wants them unique per batch
	// cgroups named by rules that did not exist when the plan was loaded.
	// Their atoms were left out; the caller should re-Apply once they show up.
	missing map[string]bool
}

const cgroupRoot = "/sys/fs/cgroup"

var errCgroupMissing = errors.New("cgroup does not exist")

// cgroupID is what the kernel compares `socket cgroupv2` against: the inode
// number of the cgroup directory.
func cgroupID(path string) (uint64, error) {
	st, err := os.Stat(cgroupRoot + "/" + path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, errCgroupMissing
		}
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("nft: no inode for %s", path)
	}
	return sys.Ino, nil
}

// CgroupExists reports whether a cgroup path is present under the v2 root.
func CgroupExists(path string) bool {
	_, err := os.Stat(cgroupRoot + "/" + path)
	return err == nil
}

// Missing lists the cgroups whose rules could not be loaded, sorted.
func (h *Handle) Missing() []string {
	out := make([]string, 0, len(h.missing))
	for cg := range h.missing {
		out = append(out, cg)
	}
	sort.Strings(out)
	return out
}

// Apply replaces any earlier egresswall table with this plan, atomically:
// the kernel either has the whole ruleset or the old one.
func Apply(p *Plan) (*Handle, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nft: %w", err)
	}
	if err := deleteTable(conn); err != nil {
		return nil, err
	}
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	h := &Handle{conn: conn, table: table, sets: map[string]*nftables.Set{}, missing: map[string]bool{}}

	for _, def := range p.Sets {
		s := &nftables.Set{
			Table:      table,
			Name:       def.Name,
			KeyType:    nftables.TypeIPAddr,
			HasTimeout: true,
		}
		if def.Family == V6 {
			s.KeyType = nftables.TypeIP6Addr
		}
		if err := conn.AddSet(s, nil); err != nil {
			return nil, fmt.Errorf("nft: set %s: %w", def.Name, err)
		}
		h.sets[def.Name] = s
	}

	chainPolicy := nftables.ChainPolicyAccept
	if p.DefaultDeny {
		chainPolicy = nftables.ChainPolicyDrop
	}
	output := conn.AddChain(&nftables.Chain{
		Name:     ChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &chainPolicy,
	})
	h.rule(output, loopbackAccept())
	if err := h.chainBody(output, p, false); err != nil {
		return nil, err
	}

	if p.Forward {
		forward := conn.AddChain(&nftables.Chain{
			Name:     ForwardChain,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookForward,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &chainPolicy,
		})
		for _, pfx := range bridgePrefixes {
			h.rule(forward, oifPrefixAccept(pfx))
		}
		if err := h.chainBody(forward, p, true); err != nil {
			return nil, err
		}
	}

	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("nft: loading ruleset: %w", err)
	}
	return h, nil
}

func (h *Handle) rule(c *nftables.Chain, exprs []expr.Any) {
	h.conn.AddRule(&nftables.Rule{Table: h.table, Chain: c, Exprs: exprs})
}

func (h *Handle) chainBody(c *nftables.Chain, p *Plan, forward bool) error {
	h.rule(c, establishedAccept())
	for _, pfx := range housekeeping {
		exprs, err := h.atomExprs(Atom{Family: familyOf(pfx), Prefix: pfx, Verdict: policy.Allow})
		if err != nil {
			return err
		}
		h.rule(c, exprs)
	}
	for _, a := range p.Atoms {
		if !a.inChain(forward) {
			continue
		}
		exprs, err := h.atomExprs(a)
		if errors.Is(err, errCgroupMissing) {
			h.missing[a.Cgroup] = true
			continue
		}
		if err != nil {
			return err
		}
		h.rule(c, exprs)
	}
	if p.DefaultDeny {
		h.rule(c, refuse(""))
	}
	return nil
}

// oifPrefixAccept matches interface names starting with pfx: the kernel
// compares only as many bytes as the cmp carries, which is how nft itself
// implements "docker*".
func oifPrefixAccept(pfx string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(pfx)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// tcpOrUDP builds an anonymous set {tcp, udp} for a port rule that named no
// protocol, and returns the lookup against it.
func (h *Handle) tcpOrUDP() ([]expr.Any, error) {
	h.anon++
	s := &nftables.Set{
		Table:     h.table,
		Name:      fmt.Sprintf("__set%d", h.anon),
		Anonymous: true,
		Constant:  true,
		KeyType:   nftables.TypeInetProto,
	}
	elems := []nftables.SetElement{{Key: []byte{unix.IPPROTO_TCP}}, {Key: []byte{unix.IPPROTO_UDP}}}
	if err := h.conn.AddSet(s, elems); err != nil {
		return nil, fmt.Errorf("nft: proto set: %w", err)
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID},
	}, nil
}

// AddAddrs puts addresses into sets and commits them in one netlink batch.
// One DNS answer can touch several sets (a name covered by several rules,
// A and AAAA records), and a flush per element would mean a syscall round
// trip per address on a host that resolves constantly.
func (h *Handle) AddAddrs(adds []Add) error {
	if len(adds) == 0 {
		return nil
	}
	bySet := map[string][]nftables.SetElement{}
	for _, a := range adds {
		if _, ok := h.sets[a.Set]; !ok {
			return fmt.Errorf("nft: no set %q", a.Set)
		}
		bySet[a.Set] = append(bySet[a.Set], nftables.SetElement{Key: a.IP.Unmap().AsSlice(), Timeout: a.TTL})
	}
	for name, elems := range bySet {
		if err := h.conn.SetAddElements(h.sets[name], elems); err != nil {
			return err
		}
	}
	return h.conn.Flush()
}

// Close removes the table. A daemon that stops on purpose should not leave a
// firewall behind that nobody is feeding DNS answers to.
func (h *Handle) Close() error {
	h.conn.DelTable(h.table)
	return h.conn.Flush()
}

// Remove deletes a leftover table, for `enforce -off` after a crash.
func Remove() (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, err
	}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	for _, t := range tables {
		if t.Name == TableName {
			conn.DelTable(t)
			return true, conn.Flush()
		}
	}
	return false, nil
}

func deleteTable(conn *nftables.Conn) error {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("nft: listing tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == TableName {
			conn.DelTable(t)
		}
	}
	return nil
}

func loopbackAccept() []expr.Any {
	lo := make([]byte, 16)
	copy(lo, "lo")
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: lo},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func establishedAccept() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func refuse(rule string) []expr.Any {
	return []expr.Any{
		&expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte(LogPrefix(rule))},
		&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
	}
}

func (h *Handle) atomExprs(a Atom) ([]expr.Any, error) {
	var e []expr.Any
	if a.Cgroup != "" {
		id, err := cgroupID(a.Cgroup)
		if err != nil {
			return nil, err
		}
		e = append(e,
			&expr.Socket{Key: expr.SocketKeyCgroupv2, Level: uint32(CgroupLevel(a.Cgroup)), Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint64(id)},
		)
	}
	if a.Family != AnyFamily {
		proto := byte(unix.NFPROTO_IPV4)
		if a.Family == V6 {
			proto = unix.NFPROTO_IPV6
		}
		e = append(e,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		)
	}
	switch {
	case a.Prefix.IsValid():
		e = append(e, daddrLoad(a.Family))
		bits := a.Prefix.Bits()
		size := 4
		if a.Family == V6 {
			size = 16
		}
		if bits < size*8 {
			mask := make([]byte, size)
			for i := 0; i < bits; i++ {
				mask[i/8] |= 0x80 >> (i % 8)
			}
			e = append(e, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(size), Mask: mask, Xor: make([]byte, size)})
		}
		e = append(e, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a.Prefix.Masked().Addr().AsSlice()})
	case a.Set != "":
		s, ok := h.sets[a.Set]
		if !ok {
			return nil, fmt.Errorf("nft: atom refers to unknown set %q", a.Set)
		}
		e = append(e, daddrLoad(a.Family), &expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID})
	}
	switch {
	case a.Proto != "":
		l4 := byte(unix.IPPROTO_TCP)
		if a.Proto == "udp" {
			l4 = unix.IPPROTO_UDP
		}
		e = append(e,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4}},
		)
	case a.Port.Hi != 0:
		lookup, err := h.tcpOrUDP()
		if err != nil {
			return nil, err
		}
		e = append(e, lookup...)
	}
	{
		if a.Port.Hi != 0 {
			// destination port sits at the same offset in tcp and udp
			e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
			if a.Port.Lo == a.Port.Hi {
				e = append(e, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: be16(a.Port.Lo)})
			} else {
				e = append(e, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: be16(a.Port.Lo), ToData: be16(a.Port.Hi)})
			}
		}
	}
	if a.Verdict == policy.Allow {
		e = append(e, &expr.Verdict{Kind: expr.VerdictAccept})
	} else {
		e = append(e, refuse(a.Rule)...)
	}
	return e, nil
}

func daddrLoad(f Family) expr.Any {
	if f == V6 {
		return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}
}

func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
