package rsa

import "testing"

func getRsa() *Rsa {
	return NewRsa(RsaConfig{})
}

func TestRsa_GenerateKey(t *testing.T) {
	r := getRsa()
	r.GenerateKey()
}

func TestRsa_Decrypt(t *testing.T) {
	r := getRsa()
	data := "abc 123 张大鹏"
	t.Log(data)

	// 加密
	encrypt, err := r.Encrypt([]byte(data))
	if err != nil {
		t.Error(err)
	}
	t.Log(encrypt)

	// 解密
	decrypt, err := r.Decrypt(encrypt)
	if err != nil {
		t.Error(err)
	}
	t.Log(decrypt)
}

func TestRsa_DecryptString(t *testing.T) {
	r := getRsa()
	data := "abc 123 张大鹏"
	t.Log(data)

	// 加密
	encrypt, err := r.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(encrypt)

	// 解密
	decrypt, err := r.DecryptString(encrypt)
	if err != nil {
		t.Error(err)
	}
	t.Log(decrypt)
}
