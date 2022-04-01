package aes

import "testing"

func getCfb() *AesCfb {
	c := NewAesCfb("1234123412341234")
	return c
}

func TestAesCfb_Decrypt(t *testing.T) {
	a := getCfb()
	data := "abc"
	t.Log(data)

	// 加密
	encrypt, err := a.Encrypt([]byte(data))
	if err != nil {
		t.Error(err)
	}
	t.Log(encrypt)

	// 解密
	decrypt, err := a.Decrypt(encrypt)
	if err != nil {
		t.Error(err)
	}
	t.Log(decrypt)
}

func TestAesCfb_DecryptString(t *testing.T) {
	a := getCfb()
	data := "abc"
	t.Log(data)

	// 加密
	encrypt, err := a.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(encrypt)

	// 解密
	decrypt, err := a.DecryptString(encrypt)
	if err != nil {
		t.Error(err)
	}
	t.Log(decrypt)
}
