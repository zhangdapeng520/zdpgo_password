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

	// sha256加密
	result, err = p.Hash.Sha256.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// sha256校验
	fmt.Println(p.Hash.Sha256.ValidateString(data, result))
}
