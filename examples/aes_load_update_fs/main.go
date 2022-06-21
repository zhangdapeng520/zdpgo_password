package main

import (
	_ "embed"
	"fmt"
	"github.com/zhangdapeng520/zdpgo_log"
	"github.com/zhangdapeng520/zdpgo_password"
	"github.com/zhangdapeng520/zdpgo_password/generator"
)

//go:embed email
var emailData []byte

func main() {
	p := zdpgo_password.New(zdpgo_log.Tmp)
	fmt.Println("============", string(emailData))

	// 读取加密数据
	var data zdpgo_password.HttpServerInfo
	err := p.AesLoadData("email", emailData, &data)
	if err != nil {
		panic(err)
	}
	fmt.Println("读取加密数据成功：", data)

	// 更新加密数据
	key := generator.DefaultGenerator.GenerateByLength(32)
	err = p.AesUpdateData("email", &data, key)
	if err != nil {
		panic(err)
	}

	// 重新加载
	err = p.AesLoadData("email", p.BytesMap["email"], &data)
	if err != nil {
		panic(err)
	}
	fmt.Println("读取更新数据成功", data)
}
