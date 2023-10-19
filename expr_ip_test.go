package nftablesutils

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetCIDRMatcher(t *testing.T) {
	ip, network, err := net.ParseCIDR(`127.0.0.1/32`)
	assert.NoError(t, err)
	assert.NotNil(t, network)
	ipToAddr, ok := netip.AddrFromSlice(ip)
	assert.True(t, ok)
	addr := ipToAddr.Unmap()
	assert.True(t, addr.Is4())
	assert.False(t, addr.Is6())
	_, err = SetCIDRMatcher(ExprDirectionDestination, `127.0.0.1/32`, false)
	assert.NoError(t, err)
}
