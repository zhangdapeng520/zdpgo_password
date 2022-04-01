package ecc

import (
	"testing"
)

func getEcc() *Ecc {
	return NewEcc()
}

// 测试加密解密
func TestEcc_Encrypt(t *testing.T) {
	ecc := getEcc()
	data := "abc 123 张大鹏"
	t.Log("原始：", []byte(data))

	// 加密
	encrypt, err := ecc.Encrypt([]byte(data))
	if err != nil {
		t.Error(err)
	}
	t.Log("加密：", encrypt)

	// 解密
	decrypt, err := ecc.Decrypt(encrypt)
	if err != nil {
		t.Error(err)
	}
	t.Log("解密：", decrypt)
}

// 测试加密解密字符串
func TestEcc_EncryptString(t *testing.T) {
	ecc := getEcc()
	data := "abc 123 张大鹏"
	t.Log("原始：", data)

	// 加密
	encrypt, err := ecc.EncryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log("加密：", encrypt)

	// 解密
	decrypt, err := ecc.DecryptString(encrypt)
	if err != nil {
		t.Error(err)
	}
	t.Log("解密：", decrypt)
}
