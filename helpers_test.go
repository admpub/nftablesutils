package nftablesutils

import (
	"testing"

	"github.com/admpub/pp/ppnocolor"
)

func TestJoinExprs(t *testing.T) {
	exprs := JoinExprs(SetProtoTCP(), SetSPort(22)).Add(DestinationPort(25), Accept())
	ppnocolor.Println(exprs)
}
