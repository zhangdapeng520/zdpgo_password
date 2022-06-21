package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password/generator"
)

/*
@Time : 2022/6/21 17:16
@Author : 张大鹏
@File : main.go
@Software: Goland2021.3.1
@Description: 测试生成密码
*/

func main() {
	for i := 0; i < 10; i++ {
		fmt.Println(generator.DefaultGenerator.GenerateByLength(uint((i + 1) * 10)))
		fmt.Println(generator.DefaultGenerator.GenerateByWeak())
		fmt.Println(generator.DefaultGenerator.GenerateByOK())
		fmt.Println(generator.DefaultGenerator.GenerateByStrong())
		fmt.Println(generator.DefaultGenerator.GenerateByVeryStrong())
		fmt.Println("================")
	}
}
