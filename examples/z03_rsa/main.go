package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_log"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	p := zdpgo_password.New(zdpgo_log.Tmp)

	data := "abc 123 张大鹏"
	fmt.Println(data)

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Rsa.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Rsa.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// SHA1模式加密解密
	result, err = p.Rsa.Sha1.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Rsa.Sha1.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
