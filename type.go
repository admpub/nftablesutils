package nftablesutils

import "github.com/google/nftables"

// TypeProtoICMP bytes.
func TypeProtoICMP() []byte {
	return []byte{0x01}
}

// TypeICMPTypeEchoRequest bytes.
func TypeICMPTypeEchoRequest() []byte {
	return []byte{0x08}
}

// TypeProtoUDP bytes.
func TypeProtoUDP() []byte {
	return []byte{0x11}
}

// TypeProtoTCP bytes.
func TypeProtoTCP() []byte {
	return []byte{0x06}
}

// TypeConntrackStateNew bytes.
func TypeConntrackStateNew() []byte {
	return []byte{0x08, 0x00, 0x00, 0x00}
}

// TypeConntrackStateEstablished bytes.
func TypeConntrackStateEstablished() []byte {
	return []byte{0x02, 0x00, 0x00, 0x00}
}

// TypeConntrackStateRelated bytes.
func TypeConntrackStateRelated() []byte {
	return []byte{0x04, 0x00, 0x00, 0x00}
}

// ConntrackStateDatatype object.
func TypeConntrackStateDatatype() nftables.SetDatatype {
	ctStateDataType := nftables.SetDatatype{Name: "ct_state", Bytes: 4}
	// nftMagic: https://git.netfilter.org/nftables/tree/src/datatype.c#n32 (arr index)
	ctStateDataType.SetNFTMagic(26)
	return ctStateDataType
}
