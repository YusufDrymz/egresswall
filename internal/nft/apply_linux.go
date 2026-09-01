//go:build linux

package nft

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

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
	h := &Handle{conn: conn, table: table, sets: map[string]*nftables.Set{}}

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
	chain := conn.AddChain(&nftables.Chain{
		Name:     ChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &chainPolicy,
	})

	add := func(exprs []expr.Any) {
		conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}
	add(loopbackAccept())
	add(establishedAccept())
	for _, a := range p.Atoms {
		exprs, err := h.atomExprs(a)
		if err != nil {
			return nil, err
		}
		add(exprs)
	}
	if p.DefaultDeny {
		add(refuse(""))
	}
	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("nft: loading ruleset: %w", err)
	}
	return h, nil
}

// AddAddr puts an address into a set for ttl. Called for every DNS answer
// that matched a domain rule, so it has to stay cheap: one netlink batch.
func (h *Handle) AddAddr(set string, ip netip.Addr, ttl time.Duration) error {
	s, ok := h.sets[set]
	if !ok {
		return fmt.Errorf("nft: no set %q", set)
	}
	ip = ip.Unmap()
	if err := h.conn.SetAddElements(s, []nftables.SetElement{{Key: ip.AsSlice(), Timeout: ttl}}); err != nil {
		return err
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
	if a.Proto != "" {
		l4 := byte(unix.IPPROTO_TCP)
		if a.Proto == "udp" {
			l4 = unix.IPPROTO_UDP
		}
		e = append(e,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{l4}},
		)
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
