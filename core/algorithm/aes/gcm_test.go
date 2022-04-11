package aes

import "testing"

func getGcm() *AesGcm {
	c := NewAesGcm("1234123412341234")
	return c
}

func TestAesGcm_Decrypt(t *testing.T) {
	a := getGcm()
	data := "abc 123 张大鹏 *&…… ，。！"
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

func TestAesGcm_DecryptString(t *testing.T) {
	a := getGcm()
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

func TestAesGcm_EncryptDataKeyNonceTag(t *testing.T) {
	a := getGcm()

	data := "abc 123 张大鹏 *&……"

	// 加密数据
	data, key, nonce, tag, err := a.EncryptDataKeyNonceTag(data)
	if err != nil {
		t.Error(err)
	}
	t.Log("data: ", data)
	t.Log("key: ", key)
	t.Log("nonce: ", nonce)
	t.Log("tag: ", tag)

	// 解密数据
	decryptString, err := a.DecryptDataKeyNonceTag(data, key, nonce, tag)
	if err != nil {
		t.Error(err)
	}
	t.Log("解密数据：", decryptString)
}

func TestAesGcm_DecryptDataKeyNonceTag(t *testing.T) {
	a := getGcm()

	// 解密Python的加密数据
	data := "SHXypu0tkjGbWB+5e0dBHMpACbeNE6/eltI="
	nonce := "maGhW6qDIQE/R/SDqTE46g=="
	tag := "1NZVFilOdjASTQPm6ILNKg=="
	key := "_ZhangDapeng520%"
	decryptString, err := a.DecryptDataKeyNonceTag(data, key, nonce, tag)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}
