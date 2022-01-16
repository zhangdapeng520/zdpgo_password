package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	passwordConfig := zdpgo_password.ZdpPasswordConfig{
		Debug: true,
	}
	p := zdpgo_password.New(passwordConfig)

	// 默认密码加密方式
	result := p.Make("123456")
	fmt.Println(result)
	// 检查
	fmt.Println(p.Check("123456", result))

	// md5密码加密方式
	result = p.Md5("123456")
	fmt.Println(result)
	// 校验
	fmt.Println(p.Md5Check("123456", result))
}
