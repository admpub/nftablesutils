package nftablesutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNetInterface(t *testing.T) {
	ipv4, ipv6, err := GetNetInterface(``)
	assert.NoError(t, err)
	t.Logf(`ipv4: %+v`, ipv4)
	t.Logf(`ipv6: %+v`, ipv6)
}
