package zdpgo_password

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"
)

func TestBigNum(t *testing.T) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	fmt.Println(max, reflect.TypeOf(max))
	s := "340282366920938463463374607431768211456"
	fmt.Println(len(s))
}

func TestSSLCreate(t *testing.T) {
	SSLCreate()
}
