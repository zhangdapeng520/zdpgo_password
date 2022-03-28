package zdpgo_password

import "testing"

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
