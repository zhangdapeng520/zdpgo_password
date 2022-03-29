package zdpgo_password

import (
	"fmt"
	"testing"
)

func getAes() *Aes {
	config := AesConfig{}
	apg := NewAes(config)
	return apg
}

// 测试aes加密
func TestAes_EncryptString(t *testing.T) {
	tool := getAes()

	// 加密
	encrypted := tool.EncryptString("{\"cmd\": 3000, \"msg\": \"ok\"}")
	fmt.Println("encrypted:", encrypted)

	// 解密
	decrypted, _ := tool.DecryptString(encrypted)
	fmt.Println("decrypted:", decrypted)
}

// 测试解密
func TestAes_DecryptString(t *testing.T) {
	// 从python复制过来的
	data := "0qg69fOjmE0oR59muWdXoWhr5d4Z0XyQaC69684mAsw="
	tool := getAes()
	decryptString, err := tool.DecryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}
