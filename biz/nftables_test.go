package biz

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

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

// sudo go test -v --count=1 -run "^TestNFTables$"
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
	c := New(nftables.TableFamilyIPv4, cfg, []uint16{8080})
	c.Init()
	err = c.ApplyDefault()
	assert.NoError(t, err)
	limits, err := utils.ParseLimits(`10+/p/s`, 100)
	assert.NoError(t, err)
	c.Do(func(conn *nftables.Conn) error {
		filterInput := rule.New(c.TableFilter(), c.ChainInput())
		exp := utils.JoinExprs(
			utils.SetProtoTCP(),
			utils.SetDPort(33306),
		).Add(limits, utils.Drop())
		_, err := filterInput.Add(conn, rule.NewData([]byte(`001`), exp))
		if err != nil {
			return err
		}
		exp = utils.JoinExprs(
			utils.SetIIF(`docker0`),
			utils.SetProtoTCP(),
			utils.SetSPort(14444),
		).Add(utils.Drop())
		_, err = filterInput.Add(conn, rule.NewData([]byte(`002`), exp))
		if err != nil {
			return err
		}

		natPrerouting := rule.New(c.TableNAT(), c.ChainPrerouting())
		exp = utils.JoinExprs(
			utils.SetOIF(`docker0`),
			utils.SetProtoTCP(),
			utils.SetDPort(14445),
			utils.SetRedirect(20444, 20445),
		)
		_, err = natPrerouting.Add(conn, rule.NewData([]byte(`101`), exp))
		if err != nil {
			return err
		}
		exp = utils.JoinExprs(
			utils.SetOIF(`docker0`),
			utils.SetProtoTCP(),
			utils.SetDPort(14445),
			utils.SetDNAT(net.ParseIP(`127.0.0.2`).To4()),
		)
		_, err = natPrerouting.Add(conn, rule.NewData([]byte(`102`), exp))
		if err != nil {
			return err
		}

		err = conn.Flush()
		if err != nil {
			return err
		}

		set := utils.GetIPv4AddrSet(c.TableFilter())
		set.Name = `test_limit`
		set.Anonymous = false
		set.Constant = false
		set.Dynamic = true
		set.HasTimeout = true
		set.Timeout = time.Hour
		err = conn.AddSet(set, []nftables.SetElement{})
		if err != nil {
			return err
		}
		exprs, err := utils.SetDynamicLimitDropSet(set, 0, `200+/b/s`, 200)
		if err != nil {
			return err
		}
		exp = utils.JoinExprs(
			utils.SetProtoTCP(),
			utils.SetDPortRange(14445, 24445),
			exprs,
		)
		conn.AddRule(&nftables.Rule{
			Table: c.TableFilter(),
			Chain: c.cInput,
			Exprs: exp,
		})
		err = conn.Flush()
		if err != nil {
			return err
		}

		rules, err := filterInput.List(conn)
		if err != nil {
			return err
		}
		var index int
		for _, rule := range rules {
			if len(rule.UserData) == 0 {
				continue
			}
			fmt.Printf("table=%q, chain=%q, position=%d, handle=%d, flags=%d, exprs=%d, userData=%q\n",
				rule.Table.Name, rule.Chain.Name,
				rule.Position, rule.Handle, rule.Flags, len(rule.Exprs), rule.UserData,
			)
			switch index {
			case 0:
				assert.Equal(t, []byte(`001`), rule.UserData)
			case 1:
				assert.Equal(t, []byte(`002`), rule.UserData)
			}
			index++
		}

		//ppnocolor.Println(rules)
		return err
	})

	testServer()
	c.Cleanup()
	_ = cfg
}
