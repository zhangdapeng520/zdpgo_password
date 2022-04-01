package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	ecc := zdpgo_password.NewEcc()
	data := "abc 123 张大鹏"
	// 加密
	encrypt, err := ecc.Encrypt([]byte(data))
	fmt.Println(encrypt, err)

	// 解密
	decrypt, err := ecc.Decrypt(encrypt)
	fmt.Println(decrypt, err)

	// 加密
	encrypt1, err := ecc.EncryptString(data)
	fmt.Println(encrypt1, err)

	// 解密
	decrypt1, err := ecc.DecryptString(encrypt1)
	fmt.Println(decrypt1, err)
}
