package zdpgo_password

import (
	"fmt"
	"testing"
)

// 测试密码的创建和校验
func TestCheckPassword(t *testing.T) {
	// 创建密码
	result := MakePassword("root")
	fmt.Println(result, len(result))

	// 校验密码
	fmt.Println(CheckPassword("root", result))
}
