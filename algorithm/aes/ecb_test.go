package aes

import (
	"fmt"
	"testing"
)

func getEcb() *AesEcb {
	//key := "123" // 注意，不要求key的长度必须是16个
	key := "123123123123123123123123123123123123" // 注意，不要求key的长度必须是16个
	fmt.Println(len(key))
	ae := NewAesEcb(key)
	fmt.Println("加密的key：", key, len(key))
	return ae
}

func TestAesEcb_Encrypt(t *testing.T) {
	ae := getEcb()
	source := "hello world"
	t.Log("原字符：", source)

	encryptCode, err := ae.Encrypt([]byte(source))
	if err != nil {
		t.Error(err)
	}
	t.Log("密文：", string(encryptCode))

	decryptCode, err := ae.Decrypt(encryptCode)
	if err != nil {
		t.Error(err)
	}
	t.Log("解密：", string(decryptCode))
}

func TestAesEcb_EncryptString(t *testing.T) {
	ae := getEcb()
	source := "hello world"
	t.Log("原字符：", source)

	encryptCode, err := ae.EncryptString(source)
	if err != nil {
		t.Error(err)
	}
	t.Log("密文：", encryptCode)

	decryptCode, err := ae.DecryptString(encryptCode)
	if err != nil {
		t.Error(err)
	}
	t.Log("解密：", decryptCode)
}
