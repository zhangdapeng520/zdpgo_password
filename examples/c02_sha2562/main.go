package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	data := "abc 123 张大鹏"
	salt := "abc123456"
	fmt.Println(data)

	// sha256加密
	result, err := zdpgo_password.Sha256EncryptString(data, salt)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// sha256校验
	fmt.Println(zdpgo_password.Sha256ValidateString(data, salt, result))     // 通过
	fmt.Println(zdpgo_password.Sha256ValidateString(data+"a", salt, result)) // 不同过
}
