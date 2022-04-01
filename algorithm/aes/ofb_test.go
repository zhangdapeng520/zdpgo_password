package aes

import "testing"

func getOfb() *AesOfb {
	c := NewAesOfb("1234123412341234")
	return c
}

func TestAesOfb_Decrypt(t *testing.T) {
	a := getOfb()
	data := "abc 123 张大鹏 *&…… 。“；"
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

func TestAesOfb_DecryptString(t *testing.T) {
	a := getOfb()
	data := "abc 123 张大鹏 *&……"
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
