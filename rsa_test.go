package zdpgo_password

import (
	"testing"
)

func getRsa() *Rsa {
	r := Rsa{}
	return &r
}

// 测试生成私钥
func TestRsa_GeneratePrivateKey(t *testing.T) {
	r := getRsa()
	r.GeneratePrivateKey(2048, "private.pem")
}

// 测试生成公钥
func TestRsa_GeneratePublicKey(t *testing.T) {
	r := getRsa()
	privateKey := r.GeneratePrivateKey(2048, "private.pem")
	r.GeneratePublicKey(privateKey, "public.pem")
}

// 同时生成公钥和私钥
func TestRsa_GenerateKey(t *testing.T) {
	r := getRsa()
	r.GenerateKey(2048, "private.pem", "public.pem")
}

// 测试加密和解密
func TestRsa_EncryptDecrypt(t *testing.T) {
	r := getRsa()
	data := "hello 张大鹏!！！"

	// 加密
	cipherText := r.Encrypt([]byte(data), "public.pem")
	t.Log(cipherText)
	t.Log(string(cipherText))

	// 解密
	result := r.Decrypt(cipherText, "private.pem")
	t.Log(result)
	t.Log(string(result))
}
