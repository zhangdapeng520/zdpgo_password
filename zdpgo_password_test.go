package zdpgo_password

import (
	"fmt"
	"testing"
)

func prepareZdpPassword() *ZdpPassword {
	passwordConfig := ZdpPasswordConfig{
		Debug: true,
	}
	p := New(passwordConfig)
	return p
}

// 密码加密
func TestZdpPassword_Make(t *testing.T) {
	p := prepareZdpPassword()
	result := p.Make("123456")
	fmt.Println(result)
}

// 密码检查
func TestZdpPassword_Check(t *testing.T) {
	p := prepareZdpPassword()
	result := p.Make("123456")
	fmt.Println(result)

	// 检查
	fmt.Println(p.Check("123456", result))
}

// md5加密
func TestZdpPassword_Md5(t *testing.T) {
	p := prepareZdpPassword()
	result := p.Md5("123456")
	fmt.Println(result)

	// 校验
	fmt.Println(p.Md5Check("123456", result))
}
