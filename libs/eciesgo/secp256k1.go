package eciesgo

import (
	"crypto/elliptic"
	"github.com/zhangdapeng520/zdpgo_password/libs/secp256k1"
)

func getCurve() elliptic.Curve {
	return secp256k1.S256()
}
