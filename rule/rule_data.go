package rule

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// RuleData is a struct that is used to create rules in a given table and chain
type RuleData struct {
	Exprs []expr.Any
	// we use rule user data to store the ID
	// we do this so we can give each rule a specific id across hosts and etc
	// handles are less deterministic without setting them explicitly and lack context (only ints)
	ID       []byte
	Handle   uint64
	Position uint64
}

func (r RuleData) ToRule(table *nftables.Table, chain *nftables.Chain) nftables.Rule {
	return nftables.Rule{
		Table:    table,
		Chain:    chain,
		Exprs:    r.Exprs,
		UserData: r.ID,
		Handle:   r.Handle,
		Position: r.Position,
	}
}

// Create a new RuleData from an ID and list of nftables expressions
func NewData(id []byte, exprs []expr.Any, handleAndPosition ...uint64) RuleData {
	var _handle uint64
	var _position uint64
	if len(handleAndPosition) > 0 {
		_handle = handleAndPosition[0]
	}
	if len(handleAndPosition) > 1 {
		_position = handleAndPosition[1]
	}
	return RuleData{
		Exprs:    exprs,
		ID:       id,
		Handle:   _handle,
		Position: _position,
	}
}
