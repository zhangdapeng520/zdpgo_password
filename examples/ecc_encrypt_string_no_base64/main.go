package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

/*
@Time : 2022/6/11 11:19
@Author : 张大鹏
@File : main.go
@Software: Goland2021.3.1
@Description:
*/

func main() {
	p := zdpgo_password.New()
	e := p.GetEcc()

	s := "abc"
	fmt.Println(s)

	// 加密数据
	encryptString, err := e.EncryptStringNoBase64(s)
	if err != nil {
		panic(err)
	}
	fmt.Println(encryptString)

	// 解密数据
	decryptString, err := e.DecryptStringNoBase64(encryptString)
	if err != nil {
		panic(err)
	}
	fmt.Println("===================")
	fmt.Println(decryptString)

	// 比较结果
	if s != decryptString {
		panic("加密前的数据和解密后的数据不一致")
	}
}
