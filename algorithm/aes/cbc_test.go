package aes

import "testing"

func getCbc() *AesCbc {
	c := NewAesCbc("1234123412341234")
	return c
}

func TestAesCbc_Decrypt(t *testing.T) {
	a := getCbc()
	data := "abc"

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
	t.Log(string(decrypt))
}

func TestAesCbc_DecryptString(t *testing.T) {
	a := getCbc()
	data := "abc"

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
