package rule

import (
	"testing"

	utils "github.com/admpub/nftablesutils"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
)

func TestNewRuleData(t *testing.T) {
	res := utils.CompareProtocolFamily(nftables.TableFamilyIPv4)
	id := []byte{0xd, 0xe, 0xa, 0xd}

	rD := NewData(id, res)
	assert.Equal(t, rD.ID, id)

	assert.Equal(t, rD.Exprs[0], &expr.Meta{Key: 0xf, SourceRegister: false, Register: 0x1})
	assert.Equal(t, rD.Exprs[1], &expr.Cmp{Op: 0x0, Register: 0x1, Data: []uint8{0x2}})
}
