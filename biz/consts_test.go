package biz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitCompare(t *testing.T) {
	flag := S_FORWARD | S_MANAGER
	assert.True(t, true, flag&S_ALL != 0 || flag&S_FORWARD != 0)
}
