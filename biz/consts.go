package biz

const (
	TableFilter = `filter`
	TableNAT    = `nat`
	TableMangle = `mangle`
	TableRaw    = `raw`
)

const (
	ChainInput       = `INPUT`
	ChainOutput      = `OUTPUT`
	ChainForward     = `FORWARD`
	ChainPreRouting  = `PREROUTING`
	ChainPostRouting = `POSTROUTING`
)

const (
	ApplyTypeHTTP = `http`
	ApplyTypeSMTP = `smtp`
	ApplyTypeDNS  = `smtp`
)

var ApplyAll = []string{ApplyTypeHTTP, ApplyTypeSMTP, ApplyTypeDNS}

const (
	S_ALL     = 0
	S_TRUST   = 1
	S_MANAGER = 2
	S_FORWARD = 4
)
