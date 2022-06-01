package zdpgo_password

import "testing"

/*
@Time : 2022/6/1 20:28
@Author : 张大鹏
@File : ecc_test.go
@Software: Goland2021.3.1
@Description:
*/

func TestEcc_EncryptDecrypt(t *testing.T) {
	p := New(&Config{})
	e := p.GetEcc()

	s := "abc"
	data := []byte(s)

	// 加密数据
	encryptData, err := e.Encrypt(data)
	if err != nil {
		panic(err)
	}

	// 解密数据
	decrypt, err := e.Decrypt(encryptData)
	if err != nil {
		panic(err)
	}

	// 比较结果
	if s != string(decrypt) {
		panic("加密前的数据和解密后的数据不一致")
	}
}

// 测试签名和校验
func TestEcc_SignVerify(t *testing.T) {
	p := New(&Config{})
	e := p.GetEcc()

	s := "abc"
	data := []byte(s)

	// 数据签名
	signData, err := e.Sign(data)
	if err != nil {
		panic(err)
	}

	// 校验数据
	flag := e.Verify(data, signData)
	if !flag {
		panic("校验结果错误")
	}
}
