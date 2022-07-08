package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	p := zdpgo_password.New()
	data := zdpgo_password.HttpServerInfo{
		Host:     "localhost",
		Port:     8888,
		Username: "zhangdapeng520",
		Password: "zhangdapeng520",
		Email:    "zhangdapeng520@qq.com",
		IsSsl:    true,
	}
	// 将对象加密保存为文件
	err := p.AesDump("email", &data)
	if err != nil {
		panic(err)
	}

	// 读取文件，解析为JSON对象
	err = p.AesLoad("email", &data)
	if err != nil {
		panic(err)
	}
	fmt.Println("读取数据成功", data)

	// 更新文件
	key := "abcdefabcdefabcdefabcdefabcdefab"
	err = p.AesUpdate("email", &data, key)
	if err != nil {
		panic(err)
	}

	// 重新加载
	err = p.AesLoad("email", &data)
	if err != nil {
		panic(err)
	}
	fmt.Println("读取更新数据成功", data)
}
