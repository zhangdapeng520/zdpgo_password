package zdpgo_password

import (
	"fmt"
	"testing"
)

func getAesPyGo() *AesPyGo {
	config := AesPyGoConfig{}
	apg := NewAesPyGo(config)
	return apg
}

// 测试aes加密
func TestAesPyGo_EncryptString(t *testing.T) {
	tool := getAesPyGo()

	// 加密
	encrypted := tool.EncryptString("{\"cmd\": 3000, \"msg\": \"ok\"}")
	fmt.Println("encrypted:", encrypted)

	// 解密
	decrypted, _ := tool.DecryptString(encrypted)
	fmt.Println("decrypted:", decrypted)
}

// 测试解密
func TestAesPyGo_DecryptString(t *testing.T) {
	// 从python复制过来的
	data := "0qg69fOjmE0oR59muWdXoWhr5d4Z0XyQaC69684mAsw="
	tool := getAesPyGo()
	decryptString, err := tool.DecryptString(data)
	if err != nil {
		t.Error(err)
	}
	t.Log(decryptString)
}
