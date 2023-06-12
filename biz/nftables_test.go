package biz

import (
	"fmt"
	"log"
	"net/http"
	"testing"

	utils "github.com/admpub/nftablesutils"
	"github.com/admpub/nftablesutils/rule"
	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
)

func testServer() {
	err := http.ListenAndServe(`:14444`, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`hello world.`))
	}))
	log.Fatal(err)
}

func TestNFTables(t *testing.T) {
	wanIface, _, _, err := utils.IPAddr()
	assert.NoError(t, err)
	assert.Equal(t, `eth0`, wanIface)
	cfg := Config{
		Enabled:          true,
		NetworkNamespace: ``,
		DefaultPolicy:    `accept`,
		MyIface:          `docker0`,
		MyPort:           0,
		TablePrefix:      `test_`,
		Ifaces:           []string{},
		TrustPorts:       []uint16{22},
		Applies:          []string{ApplyTypeDNS, ApplyTypeHTTP, ApplyTypeSMTP},
	}
	c := New(nftables.TableFamilyIPv6, cfg, []uint16{8080})
	c.Init()
	err = c.ApplyDefault()
	assert.NoError(t, err)

	c.Do(func(conn *nftables.Conn) error {
		target := rule.New(c.TableFilter(), c.ChainInput())
		exp := utils.JoinExprs(
			utils.SetProtoTCP(),
			utils.SetDPort(33306),
		).Add(utils.ExprLimits(`10+/p/s`, 100), utils.Accept())
		_, err := target.Add(conn, rule.NewData([]byte(`001`), exp))
		if err != nil {
			return err
		}
		exp = utils.JoinExprs(
			utils.SetIIF(`docker0`),
			utils.SetProtoTCP(),
			utils.SetSPort(14444),
			//[]expr.Any{utils.SourcePort(14444)},
		).Add(utils.Drop())
		_, err = target.Add(conn, rule.NewData([]byte(`002`), exp))
		if err != nil {
			return err
		}
		err = conn.Flush()
		if err != nil {
			return err
		}
		rules, err := target.List(conn)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			fmt.Printf("table=%q, chain=%q, position=%d, handle=%d, flags=%d, exprs=%d, userData=%q\n",
				rule.Table.Name, rule.Chain.Name,
				rule.Position, rule.Handle, rule.Flags, len(rule.Exprs), rule.UserData,
			)
		}

		//ppnocolor.Println(rules)
		return err
	})

	testServer()
	c.Cleanup()
	_ = cfg
}
