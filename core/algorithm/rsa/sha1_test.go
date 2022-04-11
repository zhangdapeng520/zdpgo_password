package rsa

import (
	"testing"
)

func getSha1() *RsaSha1 {
	return NewRsaSha1(RsaConfig{})
}

func TestRsaSha1_Decrypt(t *testing.T) {
	r := getSha1()
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

func TestRsaSha1_DecryptString(t *testing.T) {
	r := getSha1()
	data := "abc 123 张大鹏"
	t.Log(data)

	// 加密
	encryptString, err := r.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(encryptString)

	// 解密
	decryptString, err := r.DecryptString(encryptString)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}
