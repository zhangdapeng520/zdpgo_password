package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func getAes() *zdpgo_password.Aes {
	config := zdpgo_password.AesConfig{}
	aes := zdpgo_password.NewAes(config)
	return aes
}

// AES加密和解密
func demo1EncryptStringDecryptString() {
	aes := getAes()

	// 加密
	encrypted := aes.EncryptString("{\"cmd\": 3000, \"msg\": \"ok\"}")
	fmt.Println("encrypted:", encrypted)

	// 解密
	decrypted, _ := aes.DecryptString(encrypted)
	fmt.Println("decrypted:", decrypted)

	// 从python复制过来的
	data := "0qg69fOjmE0oR59muWdXoWhr5d4Z0XyQaC69684mAsw="
	decryptString, err := aes.DecryptString(data)
	fmt.Println("解密Python：", decryptString, err)
}

// 测试aes gcm加密和解密
func demo2EncryptGcm() {
	tool := getAes()

	// 加密
	data := "{\"cmd\": 3000, \"msg\": \"ok\"}"
	key := "_ZhangDapeng520%"
	edata, nonce, tag := tool.EncryptGcm(data, key)

	// 解密
	decrypted, err := tool.DecryptGcm(edata, key, nonce, tag)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("decrypted:", decrypted)

	// 从Python复制过来的
	edata = "nZEhJnB7h6ow7pkA1WGHS6Qf0npQtuTbr6o="
	nonce = "3KICnt6GJVxANgC2ikhTNA=="
	tag = "gZUkLzz88GTDzNvA1vfzqA=="
	decrypted, err = tool.DecryptGcm(edata, key, nonce, tag)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("从Python复制过来的:", decrypted)
}

func main() {
	//demo1EncryptStringDecryptString() // AES加密和解密
	demo2EncryptGcm()
}
