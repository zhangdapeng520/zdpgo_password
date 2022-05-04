# Golang加密解密框架

超简单的Golang密码加密解密工具

项目地址：https://github.com/zhangdapeng520/zdpgo_password

## 功能清单

- 常用HASH加密
- AES加密解密
- RSA加密解密
- ECC加密解密

## 版本历史

- v0.1.0 2022/1/1 
- v0.1.1 2022/3/2  AES加密和RSA加密
- v1.1.0 2022/4/1 ECC加密
- v1.1.1 2022/4/1 移除第三方依赖
- v1.1.2 2022/4/1 项目结构优化
- v1.1.3 2022/4/7 日志组件升级
- v1.1.4 2022/4/7 AES的GCM加密模式便捷方法
- v1.1.5 2022/4/9 新增不使用Key的MD5加密和校验方法
- v1.1.6 2022/4/1  新增URL编码和解码
- v1.1.7 2022/4/1  新增HEX编码和解码
- v1.1.8 2022/5/4  新增：文件加密解密
- v1.1.9 2022/5/4  优化：文件加密解密

## 基本使用

### hash加密

```go
package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	p := zdpgo_password.New(zdpgo_password.PasswordConfig{})

	data := "abc 123 张大鹏"
	fmt.Println(data)

	var (
		result string
		err    error
	)

	// md5加密
	result, err = p.Hash.Md5.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// hmac加密
	result, err = p.Hash.Hmac.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// sha1加密
	result, err = p.Hash.Sha1.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// sha256加密
	result, err = p.Hash.Sha256.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// sha512加密
	result, err = p.Hash.Sha512.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
```

### AES加密和解密

```go
package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	p := zdpgo_password.New(zdpgo_password.PasswordConfig{})

	data := "abc 123 张大鹏"
	fmt.Println(data)

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Aes.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// GCM模式加密解密
	result, err = p.Aes.Gcm.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Gcm.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// OFB模式加密解密
	result, err = p.Aes.Ofb.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Ofb.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// ECB模式加密解密
	result, err = p.Aes.Ecb.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Ecb.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// CFB模式加密解密
	result, err = p.Aes.Cfb.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Cfb.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// CTR模式加密解密
	result, err = p.Aes.Ctr.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Ctr.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// CBC模式加密解密
	result, err = p.Aes.Cbc.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Aes.Cbc.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
```

### RSA加密和解密

```go
package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	p := zdpgo_password.New(zdpgo_password.PasswordConfig{})

	data := "abc 123 张大鹏"
	fmt.Println(data)

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Rsa.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Rsa.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// SHA1模式加密解密
	result, err = p.Rsa.Sha1.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Rsa.Sha1.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
```

## ECC加密和解密

```go
package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func main() {
	p := zdpgo_password.New(zdpgo_password.PasswordConfig{})

	data := "abc 123 张大鹏"
	fmt.Println(data)

	var (
		result string
		err    error
	)

	// 默认加密解密
	result, err = p.Ecc.EncryptString(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	result, err = p.Ecc.DecryptString(result)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}
```