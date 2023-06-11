package nftablesutils

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// Transport protocol lengths and offsets
const (
	SrcPortOffset = 0
	DstPortOffset = 2
	PortLen       = 2
)

// IPv4 lengths and offsets
const (
	IPv4SrcOffset = 12
	IPv4DstOffset = 16
	IPv4AddrLen   = net.IPv4len
)

// IPv6 lengths and offsets
const (
	IPv6SrcOffset = 8
	IPv6DstOffset = 24
	IPv6AddrLen   = net.IPv6len
)

const (
	ConnTrackStateLen = 4
)

const (
	ProtoTCPOffset = 9
	ProtoTCPLen    = 1
)

const (
	ProtoUDPOffset = 9
	ProtoUDPLen    = 1
)

const (
	ProtoICMPOffset = 9
	ProtoICMPLen    = 1
)

// Default register and default xt_bpf version
const (
	defaultRegister = 1
	bpfRevision     = 1
)

type ExprDirection string

const (
	ExprDirectionSource      ExprDirection = `source`
	ExprDirectionDestination ExprDirection = `destination`
)

var (
	zeroXor  = binaryutil.NativeEndian.PutUint32(0)
	zeroXor6 = append(binaryutil.NativeEndian.PutUint64(0), binaryutil.NativeEndian.PutUint64(0)...)
)

// GetPayloadDirectives get expression directives based on ip version and direction
func GetPayloadDirectives(direction ExprDirection, isIPv4 bool, isIPv6 bool) (uint32, uint32, []byte) {
	switch {
	case direction == ExprDirectionSource && isIPv4:
		return IPv4SrcOffset, IPv4AddrLen, zeroXor
	case direction == ExprDirectionDestination && isIPv4:
		return IPv4DstOffset, IPv4AddrLen, zeroXor
	case direction == ExprDirectionSource && isIPv6:
		return IPv6SrcOffset, IPv6AddrLen, zeroXor6
	case direction == ExprDirectionDestination && isIPv6:
		return IPv6DstOffset, IPv6AddrLen, zeroXor6
	default:
		panic("no matched payload directive")
	}
}

// Returns a source port payload expression
func SourcePort(reg uint32) *expr.Payload {
	return ExprPayloadTransportHeader(reg, SrcPortOffset, PortLen)
}

// Returns a destination port payload expression
func DestinationPort(reg uint32) *expr.Payload {
	return ExprPayloadTransportHeader(reg, DstPortOffset, PortLen)
}

// Returns a IPv4 source address payload expression
func IPv4SourceAddress(reg uint32) *expr.Payload {
	return ExprPayloadNetHeader(reg, IPv4SrcOffset, IPv4AddrLen)
}

// Returns a IPv6 source address payload expression
func IPv6SourceAddress(reg uint32) *expr.Payload {
	return ExprPayloadNetHeader(reg, IPv6SrcOffset, IPv6AddrLen)
}

// Returns a IPv4 destination address payload expression
func IPv4DestinationAddress(reg uint32) *expr.Payload {
	return ExprPayloadNetHeader(reg, IPv4DstOffset, IPv4AddrLen)
}

// Returns a IPv6 destination address payload expression
func IPv6DestinationAddress(reg uint32) *expr.Payload {
	return ExprPayloadNetHeader(reg, IPv6DstOffset, IPv6AddrLen)
}

func ProtoTCP(reg uint32) *expr.Payload {
	return ExprPayloadNetHeader(reg, ProtoTCPOffset, ProtoTCPLen)
}

func ProtoUDP(reg uint32) *expr.Payload {
	return ExprPayloadNetHeader(reg, ProtoUDPOffset, ProtoUDPLen)
}

// Returns a port set lookup expression
func PortSetLookUp(set *nftables.Set, reg uint32) *expr.Lookup {
	return ExprLookupSet(reg, set.Name, set.ID)
}

// Returns an IP set lookup expression
func IPSetLookUp(set *nftables.Set, reg uint32) *expr.Lookup {
	return ExprLookupSet(reg, set.Name, set.ID)
}

// Returns an equal comparison expression
func Equals(data []byte, reg uint32) *expr.Cmp {
	return ExprCmpEq(reg, data)
}

// Returns a not-equal comparison expression
func NotEquals(data []byte, reg uint32) *expr.Cmp {
	return ExprCmpNeq(reg, data)
}

// Returns an accept verdict expression
func Accept() *expr.Verdict {
	return ExprAccept()
}

// Returns an drop verdict expression
func Drop() *expr.Verdict {
	return ExprDrop()
}

// Returns a xtables match expression
func Match(name string, revision uint32, info xt.InfoAny) *expr.Match {
	return &expr.Match{
		Name: name,
		Rev:  revision,
		Info: info,
	}
}

// Returns a xtables match expression of unknown type
func MatchUnknown(name string, revision uint32, info []byte) *expr.Match {
	infoBytes := xt.Unknown(info)
	return Match(name, revision, &infoBytes)
}

// Returns a xtables match bpf expression
func MatchBPF(info []byte) *expr.Match {
	return MatchUnknown("bpf", bpfRevision, info)
}

// Returns a xtables match bpf expression with a verdict
func MatchBPFWithVerdict(info []byte, verdict *expr.Verdict) []expr.Any {
	return []expr.Any{
		MatchBPF(info),
		verdict,
	}
}

func LoadCtByKeyWithRegister(ctKey expr.CtKey, reg uint32) (*expr.Ct, error) {
	// Current upper and lower bound for valid CtKey values
	if ctKey < expr.CtKeySTATE || ctKey > expr.CtKeyEVENTMASK {
		return &expr.Ct{}, fmt.Errorf("invalid CtKey given")
	}

	return &expr.Ct{
		Register: reg,
		Key:      ctKey,
	}, nil
}

func LoadCtByKey(ctKey expr.CtKey) (*expr.Ct, error) {
	return LoadCtByKeyWithRegister(ctKey, defaultRegister)
}
