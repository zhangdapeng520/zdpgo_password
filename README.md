# Golang加密解密框架

专用于加密解密的组件，以HASH和AES加密解密为主

## 安装

```bash
go get github.com/zhangdapeng520/zdpgo_password
```

## 基本用法

### sha256加密和校验

此方法可以用于一般的用户登录信息中密码的加密和校验。

```go
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
```

## 版本历史

- v0.1.0 2022/01/01
- v0.1.1 2022/03/02 AES加密和RSA加密
- v1.1.0 2022/04/01 ECC加密
- v1.1.1 2022/04/01 移除第三方依赖
- v1.1.2 2022/04/01 项目结构优化
- v1.1.3 2022/04/07 日志组件升级
- v1.1.4 2022/04/07 AES的GCM加密模式便捷方法
- v1.1.5 2022/04/09 新增不使用Key的MD5加密和校验方法
- v1.1.6 2022/04/01 新增URL编码和解码
- v1.1.7 2022/04/01 新增HEX编码和解码
- v1.1.8 2022/05/04 新增：文件加密解密
- v1.1.9 2022/05/04 优化：文件加密解密
- v1.2.0 2022/06/02 优化：ECC加密解密
- v1.2.1 2022/06/06 新增：ECC支持指定公钥和私钥
- v1.2.2 2022/06/06 新增：ECC支持获取公钥和私钥
- v1.2.3 2022/06/06 优化：多个ECC对象支持共用公钥和私钥
- v1.2.4 2022/06/11 新增：不使用base64编码的ECC加密方式
- v1.2.5 2022/06/14 优化：日志创建方式优化
- v1.2.6 2022/06/21 新增：密码生成器、密码文件生成和更新
- v1.2.7 2022/06/21 新增：加密HTTP服务信息
- v1.2.8 2022/06/21 新增：加密字节数组
- v1.2.9 2022/06/28 优化：移除日志组件
- v1.3.0 2022/07/08 优化：移除ECC、RSA、File加密解密
- v1.3.1 2022/07/08 新增：hash相关的方法

### v1.3.2

- sha256校验

### v1.3.3

- sha256加密和校验方法使用方式优化，更简单


