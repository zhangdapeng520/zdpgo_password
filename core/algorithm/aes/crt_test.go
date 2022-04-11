package aes

import "testing"

func getAesCrt() *AesCrt {
	return NewAesCrt("1234123412341234")
}

func TestAesCrt_Decrypt(t *testing.T) {
	a := getAesCrt()
	data := "123 abc 张大鹏"

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

func TestAesCrt_DecryptString(t *testing.T) {
	a := getAesCrt()
	data := "123 abc 张大鹏"
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
