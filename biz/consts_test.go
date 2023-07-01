package biz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitCompare(t *testing.T) {
	flag := SET_FORWARD | SET_MANAGER
	assert.True(t, flag&SET_ALL != 0 || flag&SET_FORWARD != 0)
	assert.True(t, flag&SET_ALL != 0 || flag&SET_MANAGER != 0)

	flag = SET_MANAGER
	assert.True(t, flag&SET_ALL != 0 || flag&SET_MANAGER != 0)

	flag = SET_FORWARD
	assert.False(t, flag&SET_ALL != 0 || flag&SET_MANAGER != 0)

	flag = SET_MANAGER
	assert.False(t, flag&SET_ALL != 0 || flag&SET_FORWARD != 0)

	flag = SET_ALL
	assert.True(t, flag&SET_ALL != 0 || flag&SET_MANAGER != 0)

	flag = 0
	assert.False(t, flag&SET_ALL != 0 || flag&SET_MANAGER != 0)
}
