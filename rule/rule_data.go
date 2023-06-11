package rule

import (
	"github.com/google/nftables/expr"
)

// RuleData is a struct that is used to create rules in a given table and chain
type RuleData struct {
	Exprs []expr.Any
	// we use rule user data to store the ID
	// we do this so we can give each rule a specific id across hosts and etc
	// handles are less deterministic without setting them explicitly and lack context (only ints)
	ID     []byte
	Handle uint64
}

// Create a new RuleData from an ID and list of nftables expressions
func NewData(id []byte, exprs []expr.Any, handle ...uint64) RuleData {
	var _handle uint64
	if len(handle) > 0 {
		_handle = handle[0]
	}
	return RuleData{
		Exprs:  exprs,
		ID:     id,
		Handle: _handle,
	}
}
