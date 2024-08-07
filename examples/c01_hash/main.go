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

	// md5加密
	result, err = p.Hash.Md5.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// hmac加密
	result, err = p.Hash.Hmac.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// sha1加密
	result, err = p.Hash.Sha1.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// sha256加密
	result, err = p.Hash.Sha256.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// sha512加密
	result, err = p.Hash.Sha512.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
