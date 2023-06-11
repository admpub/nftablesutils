package nftablesutils

import (
	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

var (
	typeProtoICMP                 = []byte{unix.IPPROTO_ICMP}
	typeProtoICMPV6               = []byte{unix.IPPROTO_ICMPV6}
	typeICMPTypeEchoRequest       = []byte{unix.IP_PKTINFO}
	typeProtoUDP                  = []byte{unix.IPPROTO_UDP}
	typeProtoTCP                  = []byte{unix.IPPROTO_TCP}
	typeConntrackStateNew         = []byte{0x08, 0x00, 0x00, 0x00}
	typeConntrackStateEstablished = []byte{0x02, 0x00, 0x00, 0x00}
	typeConntrackStateRelated     = []byte{0x04, 0x00, 0x00, 0x00}
)

// TypeProtoICMP bytes.
func TypeProtoICMP() []byte {
	return typeProtoICMP
}

// TypeProtoICMPV6 bytes.
func TypeProtoICMPV6() []byte {
	return typeProtoICMPV6
}

// TypeICMPTypeEchoRequest bytes.
func TypeICMPTypeEchoRequest() []byte {
	return typeICMPTypeEchoRequest
}

// TypeProtoUDP bytes.
func TypeProtoUDP() []byte {
	return typeProtoUDP
}

// TypeProtoTCP bytes.
func TypeProtoTCP() []byte {
	return typeProtoTCP
}

// TypeConntrackStateNew bytes.
func TypeConntrackStateNew() []byte {
	return typeConntrackStateNew
}

// TypeConntrackStateEstablished bytes.
func TypeConntrackStateEstablished() []byte {
	return typeConntrackStateEstablished
}

// TypeConntrackStateRelated bytes.
func TypeConntrackStateRelated() []byte {
	return typeConntrackStateRelated
}

// ConntrackStateDatatype object.
func TypeConntrackStateDatatype() nftables.SetDatatype {
	ctStateDataType := nftables.SetDatatype{Name: "ct_state", Bytes: 4}
	// nftMagic: https://git.netfilter.org/nftables/tree/src/datatype.c#n32 (arr index)
	ctStateDataType.SetNFTMagic(26)
	return ctStateDataType
}
