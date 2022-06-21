package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_log"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	p := zdpgo_password.New(zdpgo_log.Tmp)
	data := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{"zhangdapeng520", "zhangdapeng520"}

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
}
