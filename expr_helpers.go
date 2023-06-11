package nftablesutils

import (
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// SetIIF equals input-interface
func SetIIF(iface string) Exprs {
	exprs := []expr.Any{
		ExprIIFName(),
		ExprCmpEqIFName(iface),
	}

	return exprs
}

// SetOIF equals output-interface
func SetOIF(iface string) Exprs {
	exprs := []expr.Any{
		ExprOIFName(),
		ExprCmpEqIFName(iface),
	}

	return exprs
}

// SetNIIF not equals input-interface
func SetNIIF(iface string) Exprs {
	exprs := []expr.Any{
		ExprIIFName(),
		ExprCmpNeqIFName(iface),
	}

	return exprs
}

// SetNOIF not equals output-interface
func SetNOIF(iface string) Exprs {
	exprs := []expr.Any{
		ExprOIFName(),
		ExprCmpNeqIFName(iface),
	}

	return exprs
}

// SetCIDRMatcher generates nftables expressions that matches a CIDR
// SetCIDRMatcher(ExprDirectionSource, `127.0.0.0/24`)
func SetCIDRMatcher(direction ExprDirection, cidr string, isINet bool) []expr.Any {
	ip, network, _ := net.ParseCIDR(cidr)
	ipToAddr, _ := netip.AddrFromSlice(ip)
	addr := ipToAddr.Unmap()

	offSet, packetLen, zeroXor := GetPayloadDirectives(direction, addr.Is4(), addr.Is6())

	exprs := make([]expr.Any, 0, 5)
	if isINet {
		var family nftables.TableFamily
		if addr.Is4() {
			family = nftables.TableFamilyIPv4
		} else {
			family = nftables.TableFamilyIPv6
		}
		exprs = append(exprs, CompareProtocolFamily(family)...)
	}

	exprs = append(
		exprs,
		// fetch src add
		&expr.Payload{
			DestRegister: defaultRegister,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offSet,
			Len:          packetLen,
		},
		// net mask
		&expr.Bitwise{
			DestRegister:   defaultRegister,
			SourceRegister: defaultRegister,
			Len:            packetLen,
			Mask:           network.Mask,
			Xor:            zeroXor,
		},
		// net address
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: defaultRegister,
			Data:     addr.AsSlice(),
		},
	)
	return exprs
}

// SetSourceIPv4Net helper.
func SetSourceIPv4Net(addr []byte, mask []byte) Exprs {
	exprs := []expr.Any{
		IPv4SourceAddress(defaultRegister),
		ExprBitwise(defaultRegister, defaultRegister, IPv4AddrLen,
			mask,
			make([]byte, IPv4AddrLen),
		),
		ExprCmpEq(defaultRegister, addr),
	}
	return exprs
}

// SetProtoICMP helper.
func SetProtoICMP() Exprs {
	exprs := []expr.Any{
		ExprPayloadNetHeader(defaultRegister, ProtoICMPOffset, ProtoICMPLen),
		ExprCmpEq(defaultRegister, TypeProtoICMP()),
	}

	return exprs
}

func SetProtoICMPv6() Exprs {
	return []expr.Any{
		// payload load 1b @ network header + 6 => reg 1
		ExprPayloadNetHeader(defaultRegister, ProtoICMPv6Offset, ProtoICMPv6Len),
		// cmp eq reg 1 0x0000003a
		ExprCmpEq(defaultRegister, TypeProtoICMPV6()),
	}
}

// SetINetProtoICMP helper.
func SetINetProtoICMP() Exprs {
	exprs := []expr.Any{
		ExprMeta(expr.MetaKeyL4PROTO, defaultRegister),
		ExprCmpEq(defaultRegister, TypeProtoICMP()),
	}

	return exprs
}

func SetINetProtoICMPv6() Exprs {
	return []expr.Any{
		ExprMeta(expr.MetaKeyL4PROTO, defaultRegister),
		ExprCmpEq(defaultRegister, TypeProtoICMPV6()),
	}
}

// SetICMPTypeEchoRequest helper.
func SetICMPTypeEchoRequest() Exprs {
	exprs := []expr.Any{
		ExprPayloadTransportHeader(defaultRegister, 0, 1),
		ExprCmpEq(defaultRegister, TypeICMPTypeEchoRequest()),
	}

	return exprs
}

// SetProtoUDP helper.
func SetProtoUDP() Exprs {
	exprs := []expr.Any{
		ProtoUDP(defaultRegister),
		ExprCmpEq(defaultRegister, TypeProtoUDP()),
	}

	return exprs
}

// SetProtoTCP helper.
func SetProtoTCP() Exprs {
	exprs := []expr.Any{
		ProtoTCP(defaultRegister),
		ExprCmpEq(defaultRegister, TypeProtoTCP()),
	}

	return exprs
}

// SetSAddrSet helper.
func SetSAddrSet(s *nftables.Set) Exprs {
	exprs := []expr.Any{
		IPv4SourceAddress(defaultRegister),
		ExprLookupSet(defaultRegister, s.Name, s.ID),
	}

	return exprs
}

// SetDAddrSet helper.
func SetDAddrSet(s *nftables.Set) Exprs {
	exprs := []expr.Any{
		IPv4DestinationAddress(defaultRegister),
		ExprLookupSet(defaultRegister, s.Name, s.ID),
	}

	return exprs
}

// GetAddrSet helper.
func GetAddrSet(t *nftables.Table) *nftables.Set {
	s := &nftables.Set{
		Anonymous: true,
		Constant:  true,
		Table:     t,
		KeyType:   nftables.TypeIPAddr,
	}

	return s
}

// SetSPort helper.
func SetSPort(p uint16) Exprs {
	exprs := []expr.Any{
		SourcePort(defaultRegister),
		ExprCmpEq(defaultRegister, binaryutil.BigEndian.PutUint16(p)),
	}

	return exprs
}

// SetDPort helper.
func SetDPort(p uint16) Exprs {
	exprs := []expr.Any{
		DestinationPort(defaultRegister),
		ExprCmpEq(defaultRegister, binaryutil.BigEndian.PutUint16(p)),
	}

	return exprs
}

// SetSPortSet helper.
func SetSPortSet(s *nftables.Set) Exprs {
	exprs := []expr.Any{
		SourcePort(defaultRegister),
		ExprLookupSet(defaultRegister, s.Name, s.ID),
	}

	return exprs
}

// SetDPortSet helper.
func SetDPortSet(s *nftables.Set) Exprs {
	exprs := []expr.Any{
		DestinationPort(defaultRegister),
		ExprLookupSet(defaultRegister, s.Name, s.ID),
	}

	return exprs
}

// SetPortCmp returns a new port expression with the given matching operator.
func SetPortCmp(port uint16, op expr.CmpOp) []expr.Any {
	return []expr.Any{
		&expr.Cmp{
			Register: defaultRegister,
			Op:       op,
			Data:     binaryutil.BigEndian.PutUint16(port),
		},
	}
}

// SetPortRange returns a new port range expression.
func SetPortRange(min uint16, max uint16) []expr.Any {
	return []expr.Any{
		&expr.Cmp{
			Register: defaultRegister,
			Op:       expr.CmpOpGte,
			Data:     binaryutil.BigEndian.PutUint16(min),
		},
		&expr.Cmp{
			Register: defaultRegister,
			Op:       expr.CmpOpLte,
			Data:     binaryutil.BigEndian.PutUint16(max),
		},
	}
}

// GetPortSet helper.
func GetPortSet(t *nftables.Table) *nftables.Set {
	s := &nftables.Set{
		Anonymous: true,
		Constant:  true,
		Table:     t,
		KeyType:   nftables.TypeInetService,
	}

	return s
}

// GetPortElems helper.
func GetPortElems(ports []uint16) []nftables.SetElement {
	elems := make([]nftables.SetElement, 0, len(ports))
	for _, p := range ports {
		elems = append(elems, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(p)})
	}

	return elems
}

// SetConntrackStateSet helper.
func SetConntrackStateSet(s *nftables.Set) Exprs {
	exprs := []expr.Any{
		ExprCtState(defaultRegister),
		ExprLookupSet(defaultRegister, s.Name, s.ID),
	}

	return exprs
}

// SetConntrackStateNew helper.
func SetConntrackStateNew() Exprs {
	exprs := []expr.Any{
		ExprCtState(defaultRegister),
		ExprBitwise(defaultRegister, defaultRegister, ConnTrackStateLen,
			TypeConntrackStateNew(),
			[]byte{0x00, 0x00, 0x00, 0x00},
		),
		ExprCmpNeq(defaultRegister, []byte{0x00, 0x00, 0x00, 0x00}),
	}

	return exprs
}

// SetConntrackStateEstablished helper.
func SetConntrackStateEstablished() Exprs {
	exprs := []expr.Any{
		ExprCtState(defaultRegister),
		ExprBitwise(defaultRegister, defaultRegister, ConnTrackStateLen,
			TypeConntrackStateEstablished(),
			[]byte{0x00, 0x00, 0x00, 0x00},
		),
		ExprCmpNeq(defaultRegister, []byte{0x00, 0x00, 0x00, 0x00}),
	}

	return exprs
}

// SetConntrackStateRelated helper.
func SetConntrackStateRelated() Exprs {
	exprs := []expr.Any{
		ExprCtState(defaultRegister),
		ExprBitwise(defaultRegister, defaultRegister, ConnTrackStateLen,
			TypeConntrackStateRelated(),
			[]byte{0x00, 0x00, 0x00, 0x00},
		),
		ExprCmpNeq(defaultRegister, []byte{0x00, 0x00, 0x00, 0x00}),
	}

	return exprs
}

// GetConntrackStateSet helper.
func GetConntrackStateSet(t *nftables.Table) *nftables.Set {
	s := &nftables.Set{
		Anonymous: true,
		Constant:  true,
		Table:     t,
		KeyType:   TypeConntrackStateDatatype(),
	}

	return s
}

const (
	StateNew         = `new`
	StateEstablished = `established`
	StateRelated     = `related`
)

// GetConntrackStateSetElems helper.
func GetConntrackStateSetElems(states []string) []nftables.SetElement {
	elems := make([]nftables.SetElement, 0, len(states))
	for _, s := range states {
		switch s {
		case StateNew:
			elems = append(elems,
				nftables.SetElement{Key: TypeConntrackStateNew()})
		case StateEstablished:
			elems = append(elems,
				nftables.SetElement{Key: TypeConntrackStateEstablished()})
		case StateRelated:
			elems = append(elems,
				nftables.SetElement{Key: TypeConntrackStateRelated()})
		}
	}

	return elems
}

type Exprs []expr.Any

func (e Exprs) Add(v ...expr.Any) Exprs {
	e = append(e, v...)
	return e
}

func JoinExprs(exprs ...[]expr.Any) Exprs {
	var sum int
	for _, vals := range exprs {
		sum += len(vals)
	}
	result := make([]expr.Any, 0, sum)
	for _, vals := range exprs {
		result = append(result, vals...)
	}
	return result
}
