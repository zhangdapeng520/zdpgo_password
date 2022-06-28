package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	p := zdpgo_password.New()

	data := "abc 123 张大鹏"
	fmt.Println(data)

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Ecc.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Ecc.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
