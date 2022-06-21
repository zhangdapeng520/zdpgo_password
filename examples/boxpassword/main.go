package main

import (
	"fmt"

	password "github.com/zhangdapeng520/zdpgo_password/boxpassword"
)

// 这里是管理密码，应该从配置文件或者环境变量获取
var mastPw0 = "masterpassword"
var mastPw1 = "masterpassword1"

func main() {
	// 用户密码
	userPw := "userpassword"

	// 对用户密码进行加密
	pwHash, err := password.Hash(userPw, mastPw0, 0, password.ScryptParams{N: 32768, R: 16, P: 1}, password.DefaultParams)
	if err != nil {
		fmt.Println("Hash fail. ", err)
	}

	// 将用户密码存储到数据库

	// -------- Verify -------------
	// 从数据库获取用户密码
	// 从环境变量获取管理密码
	// 校验用户密码是否正确
	err = password.Verify(userPw, mastPw0, pwHash)
	if err != nil {
		fmt.Println("Verify fail. ", err)
	}
	fmt.Println("Success")

	// --------- Update ------------
	// 从数据库获取密码，用新的管理密码加密
	updated, err := password.UpdateMaster(mastPw1, mastPw0, 1, pwHash, password.DefaultParams)
	if err != nil {
		fmt.Println("Update fail. ", err)
	}

	// 使用新的管理密码校验
	err = password.Verify(userPw, mastPw1, updated)
	if err != nil {
		fmt.Println("Verify fail. ", err)
	}
	fmt.Println("Success verifying updated hash")
}
