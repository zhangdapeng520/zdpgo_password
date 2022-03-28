package zdpgo_password

import (
	"fmt"
	"testing"
)

func getAes() *Aes {
	a := NewAes()
	return a
}

// 测试AES加密和解密
func TestAes_EncryptDecrypt(t *testing.T) {
	a := getAes()
	data := "hello 张大鹏 !！！"

	// 加密
	result, err := a.Encrypt([]byte(data))
	t.Log(result)
	if err != nil {
		t.Error(err)
	}

	// 解密
	decrypt, err := a.Decrypt(result)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(decrypt)
}
