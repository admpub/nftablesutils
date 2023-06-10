package biz

import (
	"net"
	"runtime"

	"golang.org/x/sys/unix"

	utils "github.com/admpub/nftablesutils"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netns"
)

const loIface = "lo"

var _ INFTables = &NFTables{}

// NFTables struct.
type NFTables struct {
	cfg Config

	originNetNS netns.NsHandle
	targetNetNS netns.NsHandle

	wanIface string
	wanIP    net.IP
	myIface  string
	myPort   uint16

	tFilter  *nftables.Table
	cInput   *nftables.Chain
	cForward *nftables.Chain
	cOutput  *nftables.Chain

	tNAT         *nftables.Table
	cPostrouting *nftables.Chain

	filterSetTrustIP     *nftables.Set
	filterSetMyManagerIP *nftables.Set
	filterSetMyForwardIP *nftables.Set

	managerPorts []uint16

	applied bool
}

// Init nftables firewall.
func Init(
	cfg Config,
	managerPorts []uint16,
) (*NFTables, error) {
	// obtain default interface name, ip address and gateway ip address
	wanIface, _, wanIP, err := utils.IPAddr()
	if err != nil {
		return nil, err
	}

	defaultPolicy := nftables.ChainPolicyDrop
	if cfg.DefaultPolicy == "accept" {
		defaultPolicy = nftables.ChainPolicyAccept
	}

	tFilter := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}
	cInput := &nftables.Chain{
		Name:     "input",
		Table:    tFilter,
		Type:     nftables.ChainTypeFilter,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookInput,
		Policy:   &defaultPolicy,
	}
	cForward := &nftables.Chain{
		Name:     "forward",
		Table:    tFilter,
		Type:     nftables.ChainTypeFilter,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookForward,
		Policy:   &defaultPolicy,
	}
	cOutput := &nftables.Chain{
		Name:     "output",
		Table:    tFilter,
		Type:     nftables.ChainTypeFilter,
		Priority: nftables.ChainPriorityFilter,
		Hooknum:  nftables.ChainHookOutput,
		Policy:   &defaultPolicy,
	}

	tNAT := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "nat"}
	cPostrouting := &nftables.Chain{
		Name:     "postrouting",
		Table:    tNAT,
		Type:     nftables.ChainTypeNAT,
		Priority: nftables.ChainPriorityNATSource,
		Hooknum:  nftables.ChainHookPostrouting,
	}

	filterSetTrustIP := &nftables.Set{
		Name:    "trust_ipset",
		Table:   tFilter,
		KeyType: nftables.TypeIPAddr,
	}
	filterSetMyManagerIP := &nftables.Set{
		Name:    "mymanager_ipset",
		Table:   tFilter,
		KeyType: nftables.TypeIPAddr,
	}
	filterSetMyForwardIP := &nftables.Set{
		Name:    "myforward_ipset",
		Table:   tFilter,
		KeyType: nftables.TypeIPAddr,
	}

	nft := &NFTables{
		cfg: cfg,

		wanIface: wanIface,
		wanIP:    wanIP,
		myIface:  cfg.MyIface,
		myPort:   cfg.MyPort,

		tFilter:  tFilter,
		cInput:   cInput,
		cForward: cForward,
		cOutput:  cOutput,

		tNAT:         tNAT,
		cPostrouting: cPostrouting,

		filterSetTrustIP:     filterSetTrustIP,
		filterSetMyManagerIP: filterSetMyManagerIP,
		filterSetMyForwardIP: filterSetMyForwardIP,

		managerPorts: managerPorts,
	}

	err = nft.apply()
	if err != nil {
		return nil, err
	}

	return nft, nil
}

// networkNamespaceBind target by name.
func (nft *NFTables) networkNamespaceBind() (*nftables.Conn, error) {
	if nft.cfg.NetworkNamespace == "" {
		return &nftables.Conn{NetNS: int(nft.originNetNS)}, nil
	}

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()

	origin, err := netns.Get()
	if err != nil {
		nft.networkNamespaceRelease()
		return nil, err
	}

	nft.originNetNS = origin

	target, err := netns.GetFromName(nft.cfg.NetworkNamespace)
	if err != nil {
		nft.networkNamespaceRelease()
		return nil, err
	}

	// switch to target network namespace
	err = netns.Set(target)
	if err != nil {
		nft.networkNamespaceRelease()
		return nil, err
	}
	nft.targetNetNS = target

	return &nftables.Conn{NetNS: int(nft.targetNetNS)}, nil
}

// networkNamespaceRelease to origin.
func (nft *NFTables) networkNamespaceRelease() error {
	if nft.cfg.NetworkNamespace == "" {
		return nil
	}

	// finally unlock os thread
	defer runtime.UnlockOSThread()

	// switch back to the original namespace
	err := netns.Set(nft.originNetNS)
	if err != nil {
		return err
	}

	// close fd to origin and dev ns
	nft.originNetNS.Close()
	nft.targetNetNS.Close()

	nft.targetNetNS = 0

	return nil
}

// apply rules
func (nft *NFTables) apply() error {
	if !nft.cfg.Enabled {
		return nil
	}

	// bind network namespace if it was set in config
	c, err := nft.networkNamespaceBind()
	if err != nil {
		return err
	}

	// release network namespace finally
	defer nft.networkNamespaceRelease()

	c.FlushRuleset()
	//
	// Init Tables and Chains.
	//

	// add filter table
	// cmd: nft add table ip filter
	c.AddTable(nft.tFilter)
	// add input chain of filter table
	// cmd: nft add chain ip filter input \
	// { type filter hook input priority 0 \; policy drop\; }
	c.AddChain(nft.cInput)
	// add forward chain
	// cmd: nft add chain ip filter forward \
	// { type filter hook forward priority 0 \; policy drop\; }
	c.AddChain(nft.cForward)
	// add output chain
	// cmd: nft add chain ip filter output \
	// { type filter hook output priority 0 \; policy drop\; }
	c.AddChain(nft.cOutput)

	// add nat table
	// cmd: nft add table ip nat
	c.AddTable(nft.tNAT)
	// add postrouting chain
	// cmd: nft add chain ip nat postrouting \
	// { type nat hook postrouting priority 100 \; }
	c.AddChain(nft.cPostrouting)

	//
	// Init sets.
	//

	// add trust_ipset
	// cmd: nft add set ip filter trust_ipset { type ipv4_addr\; }
	// --
	// set trust_ipset {
	//         type ipv4_addr
	// }
	err = c.AddSet(nft.filterSetTrustIP, nil)
	if err != nil {
		return err
	}

	// add wgmanager_ipset
	// cmd: nft add set ip filter wgmanager_ipset { type ipv4_addr\; }
	// --
	// set wgmanager_ipset {
	//         type ipv4_addr
	// }
	err = c.AddSet(nft.filterSetMyManagerIP, nil)
	if err != nil {
		return err
	}

	// add wgforward_ipset
	// cmd: nft add set ip filter wgforward_ipset { type ipv4_addr\; }
	// --
	// set wgforward_ipset {
	//         type ipv4_addr
	// }
	err = c.AddSet(nft.filterSetMyForwardIP, nil)
	if err != nil {
		return err
	}

	//
	// Init filter rules.
	//

	nft.inputLocalIfaceRules(c)
	nft.outputLocalIfaceRules(c)
	if err = nft.applyCommonRules(c, nft.wanIface); err != nil {
		return err
	}
	err = nft.sdnRules(c)
	if err != nil {
		return err
	}
	err = nft.sdnForwardRules(c)
	if err != nil {
		return err
	}
	nft.natRules(c)

	for _, iface := range nft.cfg.Ifaces {
		if iface == nft.wanIface {
			continue
		}

		if err = nft.applyCommonRules(c, iface); err != nil {
			return err
		}
	}

	// apply configuration
	err = c.Flush()
	if err != nil {
		return err
	}
	nft.applied = true

	return nil
}

func (nft *NFTables) applyCommonRules(c *nftables.Conn, iface string) error {
	err := nft.inputHostBaseRules(c, nft.wanIface)
	if err != nil {
		return err
	}
	err = nft.outputHostBaseRules(c, nft.wanIface)
	if err != nil {
		return err
	}
	err = nft.inputTrustIPSetRules(c, nft.wanIface)
	if err != nil {
		return err
	}
	err = nft.outputTrustIPSetRules(c, nft.wanIface)
	if err != nil {
		return err
	}
	err = nft.inputPublicRules(c, nft.wanIface)
	if err != nil {
		return err
	}
	err = nft.outputPublicRules(c, nft.wanIface)
	return err
}

// inputLocalIfaceRules to apply.
func (nft *NFTables) inputLocalIfaceRules(c *nftables.Conn) {
	// cmd: nft add rule ip filter input meta iifname "lo" accept
	// --
	// iifname "lo" accept
	exprs := make([]expr.Any, 0, 3)
	exprs = append(exprs, utils.SetIIF(loIface)...)
	exprs = append(exprs, utils.ExprAccept())
	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter input meta iifname != "lo" \
	// ip saddr 127.0.0.0/8 reject
	// --
	// iifname != "lo" ip saddr 127.0.0.0/8 reject with icmp type prot-unreachable
	exprs = make([]expr.Any, 0, 6)
	exprs = append(exprs, utils.SetNIIF(loIface)...)
	exprs = append(exprs,
		utils.SetSourceNet([]byte{127, 0, 0, 0}, []byte{255, 255, 255, 0})...)
	exprs = append(exprs, utils.ExprReject(
		unix.NFT_REJECT_ICMP_UNREACH,
		unix.NFT_REJECT_ICMPX_UNREACH,
	))
	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)
}

// outputLocalIfaceRules to apply.
func (nft *NFTables) outputLocalIfaceRules(c *nftables.Conn) {
	// cmd: nft add rule ip filter output meta oifname "lo" accept
	// --
	// oifname "lo" accept
	exprs := make([]expr.Any, 0, 3)
	exprs = append(exprs, utils.SetOIF(loIface)...)
	exprs = append(exprs, utils.ExprAccept())
	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cOutput,
		Exprs: exprs,
	}
	c.AddRule(rule)
}

// inputHostBaseRules to apply.
func (nft *NFTables) inputHostBaseRules(c *nftables.Conn, iface string) error {
	// cmd: nft add rule ip filter input meta iifname "eth0" ip protocol icmp \
	// ct state { established, related } accept
	// --
	// iifname "eth0" ip protocol icmp ct state { established, related } accept
	ctStateSet := utils.GetConntrackStateSet(nft.tFilter)
	elems := utils.GetConntrackStateSetElems(defaultStateWithOld)
	err := c.AddSet(ctStateSet, elems)
	if err != nil {
		return err
	}

	exprs := make([]expr.Any, 0, 7)
	exprs = append(exprs, utils.SetIIF(iface)...)
	exprs = append(exprs, utils.SetProtoICMP()...)
	exprs = append(exprs, utils.SetConntrackStateSet(ctStateSet)...)
	exprs = append(exprs, utils.ExprAccept())

	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// DNS
	if err = nft.inputDNSRules(c, iface); err != nil {
		return err
	}
	// HTTP Server
	if err = nft.inputHTTPServerRules(c, iface); err != nil {
		return err
	}

	return nil
}

// outputHostBaseRules to apply.
func (nft *NFTables) outputHostBaseRules(c *nftables.Conn, iface string) error {
	// cmd: nft add rule ip filter output meta oifname "eth0" ip protocol icmp \
	// ct state { new, established } accept
	// --
	// oifname "eth0" ip protocol icmp ct state { established, new } accept
	ctStateSet := utils.GetConntrackStateSet(nft.tFilter)
	elems := utils.GetConntrackStateSetElems(defaultStateWithNew)
	err := c.AddSet(ctStateSet, elems)
	if err != nil {
		return err
	}

	exprs := make([]expr.Any, 0, 7)
	exprs = append(exprs, utils.SetOIF(iface)...)
	exprs = append(exprs, utils.SetProtoICMP()...)
	exprs = append(exprs, utils.SetConntrackStateSet(ctStateSet)...)
	exprs = append(exprs, utils.ExprAccept())

	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cOutput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// DNS
	if err = nft.outputDNSRules(c, iface); err != nil {
		return err
	}
	// HTTP Server
	if err = nft.outputHTTPServerRules(c, iface); err != nil {
		return err
	}

	return nil
}

var defaultStateWithNew = []string{utils.StateNew, utils.StateEstablished}
var defaultStateWithOld = []string{utils.StateEstablished, utils.StateRelated}

// inputTrustIPSetRules to apply.
func (nft *NFTables) inputTrustIPSetRules(c *nftables.Conn, iface string) error {
	// cmd: nft add rule ip filter input meta iifname "eth0" ip protocol icmp \
	// icmp type echo-request ip saddr @trust_ipset ct state new accept
	// --
	// iifname "eth0" icmp type echo-request ip saddr @trust_ipset ct state new accept
	exprs := make([]expr.Any, 0, 12)
	exprs = append(exprs, utils.SetIIF(iface)...)
	exprs = append(exprs, utils.SetProtoICMP()...)
	exprs = append(exprs, utils.SetICMPTypeEchoRequest()...)
	exprs = append(exprs, utils.SetSAddrSet(nft.filterSetTrustIP)...)
	exprs = append(exprs, utils.SetConntrackStateNew()...)
	exprs = append(exprs, utils.ExprAccept())
	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter input meta iifname "eth0" \
	// ip protocol tcp tcp dport { 5522 } ip saddr @trust_ipset \
	// ct state { new, established } accept
	// --
	// iifname "eth0" tcp dport { 5522 } ip saddr @trust_ipset ct state { established, new } accept
	ctStateSet := utils.GetConntrackStateSet(nft.tFilter)
	elems := utils.GetConntrackStateSetElems(defaultStateWithNew)
	err := c.AddSet(ctStateSet, elems)
	if err != nil {
		return err
	}

	portSet := utils.GetPortSet(nft.tFilter)
	err = c.AddSet(portSet, nft.cfg.trustPorts())
	if err != nil {
		return err
	}

	exprs = make([]expr.Any, 0, 11)
	exprs = append(exprs, utils.SetIIF(iface)...)
	exprs = append(exprs, utils.SetProtoTCP()...)
	exprs = append(exprs, utils.SetDPortSet(portSet)...)
	exprs = append(exprs, utils.SetSAddrSet(nft.filterSetTrustIP)...)
	exprs = append(exprs, utils.SetConntrackStateSet(ctStateSet)...)
	exprs = append(exprs, utils.ExprAccept())
	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	return nil
}

// outputTrustIPSetRules to apply.
func (nft *NFTables) outputTrustIPSetRules(c *nftables.Conn, iface string) error {
	// cmd: nft add rule ip filter output meta oifname "eth0" \
	// ip protocol tcp tcp sport { 5522 } ip daddr @trust_ipset \
	// ct state established accept
	// --
	// oifname "eth0" tcp sport { 5522 } ip daddr @trust_ipset ct state established accept
	portSet := utils.GetPortSet(nft.tFilter)
	err := c.AddSet(portSet, nft.cfg.trustPorts())
	if err != nil {
		return err
	}

	exprs := make([]expr.Any, 0, 12)
	exprs = append(exprs, utils.SetOIF(iface)...)
	exprs = append(exprs, utils.SetProtoTCP()...)
	exprs = append(exprs, utils.SetSPortSet(portSet)...)
	exprs = append(exprs, utils.SetDAddrSet(nft.filterSetTrustIP)...)
	exprs = append(exprs, utils.SetConntrackStateEstablished()...)
	exprs = append(exprs, utils.ExprAccept())
	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cOutput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	return nil
}

// inputPublicRules to apply.
func (nft *NFTables) inputPublicRules(c *nftables.Conn, iface string) error {
	// cmd: nft add rule ip filter input meta iifname "eth0" \
	// ip protocol udp udp dport 51820 accept
	// --
	// iifname "eth0" udp dport 51820 accept

	exprs := make([]expr.Any, 0, 9)
	exprs = append(exprs, utils.SetIIF(iface)...)
	exprs = append(exprs, utils.SetProtoUDP()...)
	exprs = append(exprs, utils.SetDPort(nft.myPort)...)
	exprs = append(exprs, utils.ExprAccept())
	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	return nil
}

// outputPublicRules to apply.
func (nft *NFTables) outputPublicRules(c *nftables.Conn, iface string) error {
	// cmd: nft add rule ip filter output meta oifname "eth0" \
	// ip protocol udp udp sport 51820 accept
	// --
	// oifname "eth0" udp sport 51820 accept

	exprs := make([]expr.Any, 0, 10)
	exprs = append(exprs, utils.SetOIF(iface)...)
	exprs = append(exprs, utils.SetProtoUDP()...)
	exprs = append(exprs, utils.SetSPort(nft.myPort)...)
	exprs = append(exprs, utils.ExprAccept())
	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cOutput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	return nil
}

// sdnRules to apply.
func (nft *NFTables) sdnRules(c *nftables.Conn) error {
	if len(nft.myIface) == 0 {
		return nil
	}
	// cmd: nft add rule ip filter input meta iifname "wg0" ip protocol icmp \
	// icmp type echo-request ct state new accept
	// --
	// iifname "wg0" icmp type echo-request ct state new accept
	exprs := make([]expr.Any, 0, 12)
	exprs = append(exprs, utils.SetIIF(nft.myIface)...)
	exprs = append(exprs, utils.SetProtoICMP()...)
	exprs = append(exprs, utils.SetICMPTypeEchoRequest()...)
	exprs = append(exprs, utils.SetConntrackStateNew()...)
	exprs = append(exprs, utils.ExprAccept())
	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter input meta iifname "wg0" ip protocol icmp \
	// ct state { established, related } accept
	// --
	// iifname "wg0" ip protocol icmp ct state { established, related } accept
	ctStateSet := utils.GetConntrackStateSet(nft.tFilter)
	elems := utils.GetConntrackStateSetElems(defaultStateWithOld)
	err := c.AddSet(ctStateSet, elems)
	if err != nil {
		return err
	}

	exprs = make([]expr.Any, 0, 7)
	exprs = append(exprs, utils.SetIIF(nft.myIface)...)
	exprs = append(exprs, utils.SetProtoICMP()...)
	exprs = append(exprs, utils.SetConntrackStateSet(ctStateSet)...)
	exprs = append(exprs, utils.ExprAccept())

	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter input meta iifname "wg0" \
	// ip protocol tcp tcp dport { 80, 8080 } ip saddr @mymanager_ipset \
	// ct state { new, established } accept
	// --
	// iifname "wg0" tcp dport { https, 8443 } ip saddr @mymanager_ipset ct state { established, new } accept
	ctStateSet = utils.GetConntrackStateSet(nft.tFilter)
	elems = utils.GetConntrackStateSetElems(defaultStateWithNew)
	err = c.AddSet(ctStateSet, elems)
	if err != nil {
		return err
	}

	portSet := utils.GetPortSet(nft.tFilter)
	portSetElems := make([]nftables.SetElement, len(nft.managerPorts))
	for i, p := range nft.managerPorts {
		portSetElems[i] = nftables.SetElement{
			Key: binaryutil.BigEndian.PutUint16(p)}
	}
	err = c.AddSet(portSet, portSetElems)
	if err != nil {
		return err
	}

	exprs = make([]expr.Any, 0, 9)
	exprs = append(exprs, utils.SetIIF(nft.myIface)...)
	exprs = append(exprs, utils.SetProtoTCP()...)
	exprs = append(exprs, utils.SetDPortSet(portSet)...)
	exprs = append(exprs, utils.SetSAddrSet(nft.filterSetMyManagerIP)...)
	exprs = append(exprs, utils.SetConntrackStateSet(ctStateSet)...)
	exprs = append(exprs, utils.ExprAccept())
	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cInput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter output meta oifname "wg0" ip protocol icmp \
	// ct state { new, established } accept
	// --
	// oifname "wg0" ip protocol icmp ct state { established, new } accept
	ctStateSet = utils.GetConntrackStateSet(nft.tFilter)
	elems = utils.GetConntrackStateSetElems(defaultStateWithNew)
	err = c.AddSet(ctStateSet, elems)
	if err != nil {
		return err
	}

	exprs = make([]expr.Any, 0, 7)
	exprs = append(exprs, utils.SetOIF(nft.myIface)...)
	exprs = append(exprs, utils.SetProtoICMP()...)
	exprs = append(exprs, utils.SetConntrackStateSet(ctStateSet)...)
	exprs = append(exprs, utils.ExprAccept())

	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cOutput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter output meta oifname "wg0" \
	// ip protocol tcp tcp sport { 80, 8080 } ip daddr @mymanager_ipset \
	// ct state established accept
	// --
	// oifname "wg0" tcp sport { https, 8443 } ct state established accept
	portSet = utils.GetPortSet(nft.tFilter)
	portSetElems = make([]nftables.SetElement, len(nft.managerPorts))
	for i, p := range nft.managerPorts {
		portSetElems[i] = nftables.SetElement{
			Key: binaryutil.BigEndian.PutUint16(p)}
	}
	err = c.AddSet(portSet, portSetElems)
	if err != nil {
		return err
	}

	exprs = make([]expr.Any, 0, 10)
	exprs = append(exprs, utils.SetOIF(nft.myIface)...)
	exprs = append(exprs, utils.SetProtoTCP()...)
	exprs = append(exprs, utils.SetSPortSet(portSet)...)
	exprs = append(exprs, utils.SetDAddrSet(nft.filterSetMyManagerIP)...)
	exprs = append(exprs, utils.SetConntrackStateEstablished()...)
	exprs = append(exprs, utils.ExprAccept())
	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cOutput,
		Exprs: exprs,
	}
	c.AddRule(rule)

	return nil
}

// sdnForwardRules to apply.
func (nft *NFTables) sdnForwardRules(c *nftables.Conn) error {
	// cmd: nft add rule ip filter forward \
	// ip protocol tcp tcp sport 25 drop
	// --
	// tcp sport smtp drop;
	exprs := make([]expr.Any, 0, 10)
	exprs = append(exprs, utils.SetProtoTCP()...)
	exprs = append(exprs, utils.SetSPort(25)...)
	exprs = append(exprs, utils.ExprDrop())
	rule := &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cForward,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter forward \
	// meta iifname "wg0" \
	// ip saddr @wgforward_ipset \
	// meta oifname "eth0" \
	// accept
	// --
	// iifname "wg0" oifname "eth0" accept;
	exprs = make([]expr.Any, 0, 10)
	exprs = append(exprs, utils.SetIIF(nft.myIface)...)
	exprs = append(exprs, utils.SetSAddrSet(nft.filterSetMyForwardIP)...)
	exprs = append(exprs, utils.SetOIF(nft.wanIface)...)
	exprs = append(exprs, utils.ExprAccept())
	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cForward,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter forward \
	// ct state { established, related } accept
	// --
	// ct state { established, related } accept;
	ctStateSet := utils.GetConntrackStateSet(nft.tFilter)
	elems := utils.GetConntrackStateSetElems(defaultStateWithOld)
	err := c.AddSet(ctStateSet, elems)
	if err != nil {
		return err
	}

	exprs = make([]expr.Any, 0, 10)
	exprs = append(exprs, utils.SetIIF(nft.wanIface)...)
	exprs = append(exprs, utils.SetDAddrSet(nft.filterSetMyForwardIP)...)
	exprs = append(exprs, utils.SetOIF(nft.myIface)...)
	exprs = append(exprs, utils.SetConntrackStateSet(ctStateSet)...)
	exprs = append(exprs, utils.ExprAccept())
	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cForward,
		Exprs: exprs,
	}
	c.AddRule(rule)

	// cmd: nft add rule ip filter forward \
	// meta iifname "wg0" \
	// meta oifname "wg0" \
	// accept
	// --
	// iifname "wg0" oifname "wg0" accept;
	exprs = make([]expr.Any, 0, 10)
	exprs = append(exprs, utils.SetIIF(nft.myIface)...)
	exprs = append(exprs, utils.SetOIF(nft.myIface)...)
	exprs = append(exprs, utils.ExprAccept())
	rule = &nftables.Rule{
		Table: nft.tFilter,
		Chain: nft.cForward,
		Exprs: exprs,
	}
	c.AddRule(rule)

	return nil
}

// natRules to apply.
func (nft *NFTables) natRules(c *nftables.Conn) {
	// cmd: nft add rule ip nat postrouting meta oifname "eth0" \
	// snat 192.168.0.1
	// --
	// oifname "eth0" snat to 192.168.15.11
	exprs := make([]expr.Any, 0, 10)
	exprs = append(exprs, utils.SetOIF(nft.wanIface)...)
	exprs = append(exprs, utils.ExprImmediate(nft.wanIP))
	exprs = append(exprs, utils.ExprSNAT(1, 0))
	rule := &nftables.Rule{
		Table: nft.tNAT,
		Chain: nft.cPostrouting,
		Exprs: exprs,
	}
	c.AddRule(rule)
}

// UpdateTrustIPs updates filterSetTrustIP.
func (nft *NFTables) UpdateTrustIPs(del, add []net.IP) error {
	if !nft.applied {
		return nil
	}

	return nft.updateIPSet(nft.filterSetTrustIP, del, add)
}

// UpdateMyManagerIPs updates filterSetMyManagerIP.
func (nft *NFTables) UpdateMyManagerIPs(del, add []net.IP) error {
	if !nft.applied {
		return nil
	}

	return nft.updateIPSet(nft.filterSetMyManagerIP, del, add)
}

// UpdateMyForwardWanIPs updates filterSetMyForwardIP.
func (nft *NFTables) UpdateMyForwardWanIPs(del, add []net.IP) error {
	if !nft.applied {
		return nil
	}

	return nft.updateIPSet(nft.filterSetMyForwardIP, del, add)
}

func (nft *NFTables) updateIPSet(set *nftables.Set, del, add []net.IP) error {
	// bind network namespace if it was set in config
	c, err := nft.networkNamespaceBind()
	if err != nil {
		return err
	}
	// release network namespace finally
	defer nft.networkNamespaceRelease()

	if len(del) > 0 {
		elements := make([]nftables.SetElement, len(del))
		for i, v := range del {
			elements[i] = nftables.SetElement{Key: v}
		}
		err = c.SetDeleteElements(set, elements)
		if err != nil {
			return err
		}
	}

	if len(add) > 0 {
		elements := make([]nftables.SetElement, len(add))
		for i, v := range add {
			elements[i] = nftables.SetElement{Key: v}
		}
		err = c.SetAddElements(set, elements)
		if err != nil {
			return err
		}
	}

	return c.Flush()
}

// Cleanup rules to default policy filtering.
func (nft *NFTables) Cleanup() error {
	if !nft.cfg.Enabled {
		return nil
	}
	// bind network namespace if it was set in config
	c, err := nft.networkNamespaceBind()
	if err != nil {
		return err
	}
	// release network namespace finally
	defer nft.networkNamespaceRelease()

	filterSetTrustElements, _ := c.GetSetElements(nft.filterSetTrustIP) // omit error

	c.FlushRuleset()

	// add filter table
	// cmd: nft add table ip filter
	c.AddTable(nft.tFilter)
	// add input chain of filter table
	// cmd: nft add chain ip filter input \
	// { type filter hook input priority 0 \; policy drop\; }
	c.AddChain(nft.cInput)
	// add forward chain
	// cmd: nft add chain ip filter forward \
	// { type filter hook forward priority 0 \; policy drop\; }
	c.AddChain(nft.cForward)
	// add output chain
	// cmd: nft add chain ip filter output \
	// { type filter hook output priority 0 \; policy drop\; }
	c.AddChain(nft.cOutput)

	// add trust_ipset
	// cmd: nft add set ip filter trust_ipset { type ipv4_addr\; }
	err = c.AddSet(nft.filterSetTrustIP, nil)
	if err != nil {
		return err
	}

	if filterSetTrustElements != nil {
		_ = c.SetAddElements(nft.filterSetTrustIP, filterSetTrustElements) // omit error
	}

	nft.inputLocalIfaceRules(c)
	nft.outputLocalIfaceRules(c)
	_ = nft.inputHostBaseRules(c, nft.wanIface)    // omit error
	_ = nft.outputHostBaseRules(c, nft.wanIface)   // omit error
	_ = nft.inputTrustIPSetRules(c, nft.wanIface)  // omit error
	_ = nft.outputTrustIPSetRules(c, nft.wanIface) // omit error
	for _, iface := range nft.cfg.Ifaces {
		if iface == nft.wanIface {
			continue
		}

		_ = nft.inputHostBaseRules(c, iface)    // omit error
		_ = nft.outputHostBaseRules(c, iface)   // omit error
		_ = nft.inputTrustIPSetRules(c, iface)  // omit error
		_ = nft.outputTrustIPSetRules(c, iface) // omit error
	}

	// apply configuration
	err = c.Flush()
	if err != nil {
		return err
	}
	nft.applied = false

	return nil
}

// WanIP returns ip address of wan interface.
func (nft *NFTables) WanIP() net.IP {
	return nft.wanIP
}

// IfacesIPs returns ip addresses list of additional ifaces.
func (nft *NFTables) IfacesIPs() ([]net.IP, error) {
	ips := make([]net.IP, 0, len(nft.cfg.Ifaces))

	for _, v := range nft.cfg.Ifaces {
		if v == nft.wanIface || v == nft.myIface {
			continue
		}

		iface, err := net.InterfaceByName(v)
		if err != nil {
			return nil, err
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}

func (nft *NFTables) TableFilter() *nftables.Table {
	return nft.tFilter
}

func (nft *NFTables) ChainInput() *nftables.Chain {
	return nft.cInput
}

func (nft *NFTables) ChainForward() *nftables.Chain {
	return nft.cForward
}

func (nft *NFTables) ChainOutput() *nftables.Chain {
	return nft.cOutput
}

func (nft *NFTables) NATFilter() *nftables.Table {
	return nft.tNAT
}

func (nft *NFTables) ChainPostrouting() *nftables.Chain {
	return nft.cPostrouting
}

func (nft *NFTables) FilterSetTrustIP() *nftables.Set {
	return nft.filterSetTrustIP
}

func (nft *NFTables) FilterSetMyManagerIP() *nftables.Set {
	return nft.filterSetMyManagerIP
}

func (nft *NFTables) FilterSetMyForwardIP() *nftables.Set {
	return nft.filterSetMyForwardIP
}

func (nft *NFTables) Do(f func(conn *nftables.Conn) error) error {
	// bind network namespace if it was set in config
	c, err := nft.networkNamespaceBind()
	if err != nil {
		return err
	}
	// release network namespace finally
	defer nft.networkNamespaceRelease()
	return f(c)
}
