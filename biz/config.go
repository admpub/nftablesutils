package biz

import (
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
)

// Config for nftables.
type Config struct {
	Enabled          bool
	NetworkNamespace string
	DefaultPolicy    string // accept / drop
	TablePrefix      string
	MyIface          string
	MyPort           uint16
	Ifaces           []string
	TrustPorts       []uint16
}

func (c *Config) trustPorts() []nftables.SetElement {
	elems := make([]nftables.SetElement, len(c.TrustPorts))
	for i, p := range c.TrustPorts {
		elems[i] = nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(p)}
	}

	return elems
}
