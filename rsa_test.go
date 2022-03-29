package zdpgo_password

import (
	"testing"
)

func getRsa() *Rsa {
	r := NewRsa(RsaConfig{
		PrivateKeyPath: "private.pem",
		PublicKeyPath:  "public.pem",
		BitSize:        2048,
	})
	return r
}

// 测试生成私钥
func TestRsa_GeneratePrivateKey(t *testing.T) {
	r := getRsa()
	r.GeneratePrivateKey()
}

// 测试生成公钥
func TestRsa_GeneratePublicKey(t *testing.T) {
	r := getRsa()
	privateKey := r.GeneratePrivateKey()
	r.GeneratePublicKey(privateKey)
}

// 同时生成公钥和私钥
func TestRsa_GenerateKey(t *testing.T) {
	r := getRsa()
	r.GenerateKey()
}

// 测试加密和解密
func TestRsa_EncryptDecrypt(t *testing.T) {
	r := getRsa()
	data := "hello 张大鹏!！！"

	// 加密
	cipherText := r.Encrypt([]byte(data))
	t.Log(cipherText)

	// 解密
	result := r.Decrypt(cipherText)
	t.Log(result)
}

// 测试加密
func TestRsa_EncryptSha1(t *testing.T) {
	r := getRsa()
	data := "abc 123 张大鹏"

	// 加密
	result, err := r.EncryptSha1(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)
}

// 测试解密
func TestRsa_DecryptSha1(t *testing.T) {
	r := getRsa()
	data := "j+Lc1OtOu+rF9d+cKvU7IUmQ/WNTQk20t5mEABcT2liWPic2KIuF8jbQrstBdvh7zmj1KIYf5z6PD9CNCfLPnthD6k1+tLVBWPkCj3x6LVrURInJRJTHh6QrcvxM1ZmT563/D0okw9O0cr8Qc3nMDT2/dUTEpzShT3dPG76ztoX4nSd4MMEbBIOTT3G7deglwMZNDVMfUmgLz2WTa2lijfTrL7rpGcD0ofeqjUXmYPo6OV0dQV6A1myJqcSHTGNcmwvaZhGVxrKW87nB5ZJnZcYkLfpm+1YFr93iR+Qj1ygjhTqnX5pwxyoNg090/1omvXYv8jSq2mhArAVncRl7KA=="

	// 解密
	result, err := r.DecryptSha1(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(result)

	// 解密使用python加密的字符串

}

// 测试签名和校验
func TestRsa_SignVerify(t *testing.T) {
	r := getRsa()
	data := "hello 张大鹏!！！"

	// 签名
	signer := r.Sign(data)
	t.Log(signer)

	// 校验
	flag := r.Verify(data, signer)
	t.Log(flag)
}
