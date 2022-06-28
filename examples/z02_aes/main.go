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
	result, err = p.Aes.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// GCM模式加密解密
	result, err = p.Aes.Gcm.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Gcm.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// OFB模式加密解密
	result, err = p.Aes.Ofb.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Ofb.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// ECB模式加密解密
	result, err = p.Aes.Ecb.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Ecb.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// CFB模式加密解密
	result, err = p.Aes.Cfb.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Cfb.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// CTR模式加密解密
	result, err = p.Aes.Ctr.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Ctr.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// CBC模式加密解密
	result, err = p.Aes.Cbc.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Cbc.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
