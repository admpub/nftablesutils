package nftablesutils

import (
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// Returns a source port payload expression
func SourcePort(reg uint32) *expr.Payload {
	return ExprPayloadTransportHeader(reg, SrcPortOffset, PortLen)
}

// Returns a destination port payload expression
func DestinationPort(reg uint32) *expr.Payload {
	return ExprPayloadTransportHeader(reg, DstPortOffset, PortLen)
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

// ExprPortCmp returns a new port expression with the given matching operator.
func ExprPortCmp(port uint16, op expr.CmpOp) *expr.Cmp {
	return &expr.Cmp{
		Register: defaultRegister,
		Op:       op,
		Data:     binaryutil.BigEndian.PutUint16(port),
	}
}

// SetSPortRange returns a new port range expression.
func SetSPortRange(min uint16, max uint16) []expr.Any {
	return []expr.Any{
		SourcePort(defaultRegister),
		ExprPortCmp(min, expr.CmpOpGte),
		ExprPortCmp(max, expr.CmpOpLte),
	}
}

// SetDPortRange returns a new port range expression.
func SetDPortRange(min uint16, max uint16) []expr.Any {
	return []expr.Any{
		DestinationPort(defaultRegister),
		ExprPortCmp(min, expr.CmpOpGte),
		ExprPortCmp(max, expr.CmpOpLte),
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
	elems := make([]nftables.SetElement, len(ports))
	for i, p := range ports {
		elems[i] = nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(p)}
	}
	return elems
}
