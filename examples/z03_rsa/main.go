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
