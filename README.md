# zdpgo_password
超简单的Golang密码加密解密工具

项目地址：https://github.com/zhangdapeng520/zdpgo_password

## 版本历史
- 2022年1月16日 版本0.1.0
- 2022年3月29日 版本0.1.1 AES加密和RSA加密


## 基本使用
### 案例1：快速入门
```go
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
```

### 案例2：AES加密和解密
```go
package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func getAes() *zdpgo_password.Aes {
	config := zdpgo_password.AesConfig{}
	aes := zdpgo_password.NewAes(config)
	return aes
}

// AES加密和解密
func demo1EncryptStringDecryptString() {
	aes := getAes()

	// 加密
	encrypted := aes.EncryptString("{\"cmd\": 3000, \"msg\": \"ok\"}")
	fmt.Println("encrypted:", encrypted)

	// 解密
	decrypted, _ := aes.DecryptString(encrypted)
	fmt.Println("decrypted:", decrypted)

	// 从python复制过来的
	data := "0qg69fOjmE0oR59muWdXoWhr5d4Z0XyQaC69684mAsw="
	decryptString, err := aes.DecryptString(data)
	fmt.Println("解密Python：", decryptString, err)
}

// 测试aes gcm加密和解密
func demo2EncryptGcm() {
	tool := getAes()

	// 加密
	data := "{\"cmd\": 3000, \"msg\": \"ok\"}"
	key := "_ZhangDapeng520%"
	edata, nonce, tag := tool.EncryptGcm(data, key)

	// 解密
	decrypted, err := tool.DecryptGcm(edata, key, nonce, tag)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("decrypted:", decrypted)

	// 从Python复制过来的
	edata = "nZEhJnB7h6ow7pkA1WGHS6Qf0npQtuTbr6o="
	nonce = "3KICnt6GJVxANgC2ikhTNA=="
	tag = "gZUkLzz88GTDzNvA1vfzqA=="
	decrypted, err = tool.DecryptGcm(edata, key, nonce, tag)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("从Python复制过来的:", decrypted)
}

func main() {
	//demo1EncryptStringDecryptString() // AES加密和解密
	demo2EncryptGcm()
}
```

### 案例3：RSA加密和解密
```go
package main

import (
	"fmt"
	"github.com/zhangdapeng520/zdpgo_password"
)

func getRsa() *zdpgo_password.Rsa {
	r := zdpgo_password.NewRsa(zdpgo_password.RsaConfig{
		PrivateKeyPath: "private.pem",
		PublicKeyPath:  "public.pem",
		BitSize:        2048,
	})
	return r
}

// RSA加密和解密
func demo1() {
	r := getRsa()
	data := "hello 张大鹏!！！"

	// 加密
	cipherText := r.Encrypt([]byte(data))
	fmt.Println(cipherText)

	// 解密
	result := r.Decrypt(cipherText)
	fmt.Println(result)
}

func demo2() {
	r := getRsa()
	data := "abc 123 张大鹏"

	// 加密
	result, err := r.EncryptSha1(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
	data = "j+Lc1OtOu+rF9d+cKvU7IUmQ/WNTQk20t5mEABcT2liWPic2KIuF8jbQrstBdvh7zmj1KIYf5z6PD9CNCfLPnthD6k1+tLVBWPkCj3x6LVrURInJRJTHh6QrcvxM1ZmT563/D0okw9O0cr8Qc3nMDT2/dUTEpzShT3dPG76ztoX4nSd4MMEbBIOTT3G7deglwMZNDVMfUmgLz2WTa2lijfTrL7rpGcD0ofeqjUXmYPo6OV0dQV6A1myJqcSHTGNcmwvaZhGVxrKW87nB5ZJnZcYkLfpm+1YFr93iR+Qj1ygjhTqnX5pwxyoNg090/1omvXYv8jSq2mhArAVncRl7KA=="

	// 解密
	result, err = r.DecryptSha1(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)

	// 解密使用python加密的字符串
	data = "S1j7yD+RlmQjeari4qoxLGzEO+BAPUOY2IOnqD7rEygfaDGy4ansvCTwKNfmfEpotS1KCkdcfliESkoQ/cw27Rm6AMPAMfQRqh2b4SqIpZTDG1dI4zkrL+zXSMXwDcaOerkLVFrLC2OUHBBf8Bry+dKUHw6ts3XkdrQZzHSgKfNwY6dRZlElbJL2M7zO0ciRF/r69+Ct4xX0u/Ctf+VlkL5+iYmt2HT04ydPp4h3FCAzDr8rx/Ms59pOvCgU/qrDBLyRudlvjooIB7VZFql7cqkUvjSew5EK4C4GAehJkwD+Nrq6sTb9dU3Db4EbtuuVUKdgNcV7HNrhs+9NlwqGLg=="
	result, err = r.DecryptSha1(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}

func main() {
	//demo1() // RSA加密和解密
	demo2() // RSA SHA1加密和解密
}
```