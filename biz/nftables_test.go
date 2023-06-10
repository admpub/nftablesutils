package biz

import (
	"testing"

	utils "github.com/admpub/nftablesutils"
	"github.com/stretchr/testify/assert"
)

func TestNFTables(t *testing.T) {
	wanIface, _, _, err := utils.IPAddr()
	assert.NoError(t, err)
	assert.Equal(t, `eth0`, wanIface)
	cfg := Config{
		Enabled:          true,
		NetworkNamespace: ``,
		DefaultPolicy:    `accept`,
		MyIface:          ``,
		MyPort:           0,
		Ifaces:           []string{},
		TrustPorts:       []uint16{22},
	}
	c, err := Init(cfg, []uint16{8080})
	assert.NoError(t, err)
	c.Cleanup()
	_ = cfg
}
